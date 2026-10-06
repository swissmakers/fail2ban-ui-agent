// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callback

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

type snap = map[string]map[string]struct{}

func TestDiffSnapshots(t *testing.T) {
	cases := []struct {
		name       string
		prev, cur  snap
		wantBans   []edge
		wantUnbans []edge
	}{
		{
			name:       "ban and unban in a shared jail",
			prev:       snap{"ssh": {"1.1.1.1": {}, "2.2.2.2": {}}},
			cur:        snap{"ssh": {"2.2.2.2": {}, "3.3.3.3": {}}},
			wantBans:   []edge{{jail: "ssh", ip: "3.3.3.3"}},
			wantUnbans: []edge{{jail: "ssh", ip: "1.1.1.1"}},
		},
		{
			name: "jail appearing after a reload is not a ban flood",
			prev: snap{"ssh": {}},
			cur:  snap{"ssh": {}, "nginx": {"4.4.4.4": {}, "5.5.5.5": {}}},
		},
		{
			name: "jail vanishing during a reload is not an unban flood",
			prev: snap{"ssh": {"1.1.1.1": {}}, "nginx": {"4.4.4.4": {}}},
			cur:  snap{"ssh": {"1.1.1.1": {}}},
		},
		{
			name:     "sorted by jail then ip",
			prev:     snap{"b": {}, "a": {}},
			cur:      snap{"b": {"9.9.9.9": {}, "1.1.1.1": {}}, "a": {"5.5.5.5": {}}},
			wantBans: []edge{{"a", "5.5.5.5"}, {"b", "1.1.1.1"}, {"b", "9.9.9.9"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bans, unbans := diffSnapshots(tc.prev, tc.cur)
			if !reflect.DeepEqual(bans, tc.wantBans) || !reflect.DeepEqual(unbans, tc.wantUnbans) {
				t.Fatalf("diff = %v / %v, want %v / %v", bans, unbans, tc.wantBans, tc.wantUnbans)
			}
		})
	}
}

func TestSnapshotFromJailInfos(t *testing.T) {
	s := snapshotFromJailInfos([]model.JailInfo{
		{JailName: "ssh", BannedIPs: []string{" 10.0.0.1 ", ""}},
		{JailName: "", BannedIPs: []string{"9.9.9.9"}},
	})
	if len(s) != 1 || len(s["ssh"]) != 1 {
		t.Fatalf("snapshot = %#v", s)
	}
	if _, ok := s["ssh"]["10.0.0.1"]; !ok {
		t.Fatal("expected 10.0.0.1 in ssh")
	}
}

func TestEventID(t *testing.T) {
	seen := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	// Pinned: changing the derivation breaks deduplication of events queued across an agent upgrade.
	if got := eventID("srv-1", "ban", "sshd", "203.0.113.7", seen); got != "3cf453a0a2aabe31957d9a99a5f8e2ba" {
		t.Fatalf("eventID = %s", got)
	}
	if eventID("srv-1", "ban", "sshd", "203.0.113.7", seen.Add(time.Nanosecond)) == eventID("srv-1", "ban", "sshd", "203.0.113.7", seen) {
		t.Fatal("a later observation must get a new ID")
	}
	if eventID("srv-1", "unban", "sshd", "203.0.113.7", seen) == eventID("srv-1", "ban", "sshd", "203.0.113.7", seen) {
		t.Fatal("ban and unban of the same observation must differ")
	}
}

func ids(q []event) []string {
	out := []string{}
	for _, e := range q {
		out = append(out, e.id)
	}
	return out
}

func TestEnqueue(t *testing.T) {
	mk := func(names ...string) []event {
		var out []event
		for _, n := range names {
			out = append(out, event{id: n})
		}
		return out
	}
	cases := []struct {
		name        string
		queue, add  []event
		max         int
		want        []string
		wantDropped int
	}{
		{"fits", mk("a"), mk("b"), 3, []string{"a", "b"}, 0},
		{"drops oldest first", mk("a", "b"), mk("c", "d", "e"), 3, []string{"c", "d", "e"}, 2},
		{"new batch larger than max", nil, mk("a", "b", "c", "d"), 2, []string{"c", "d"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, dropped := enqueue(tc.queue, tc.add, tc.max)
			if !reflect.DeepEqual(ids(got), tc.want) || dropped != tc.wantDropped {
				t.Fatalf("enqueue = %v (dropped %d), want %v (dropped %d)", ids(got), dropped, tc.want, tc.wantDropped)
			}
		})
	}
}

func TestDropExpiredAndKeepServer(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	q := []event{
		{id: "old", serverID: "a", firstSeen: now.Add(-eventTTL)},
		{id: "fresh", serverID: "b", firstSeen: now.Add(-eventTTL + time.Second)},
		{id: "new", serverID: "a", firstSeen: now},
	}
	kept, expired := dropExpired(append([]event(nil), q...), now, eventTTL)
	if !reflect.DeepEqual(ids(kept), []string{"fresh", "new"}) || expired != 1 {
		t.Fatalf("dropExpired = %v, %d", ids(kept), expired)
	}
	if got := ids(keepServer(append([]event(nil), q...), "a")); !reflect.DeepEqual(got, []string{"old", "new"}) {
		t.Fatalf("keepServer = %v", got)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		status int
		err    error
		want   outcome
	}{
		{0, errors.New("connection refused"), outcomeRetry},
		{200, nil, outcomeDelivered},
		{204, nil, outcomeDelivered},
		{302, nil, outcomeRetry},
		{400, nil, outcomeRejected},
		{401, nil, outcomeRetry},
		{403, nil, outcomeRetry},
		{404, nil, outcomeRejected},
		{408, nil, outcomeRetry},
		{422, nil, outcomeRejected},
		{425, nil, outcomeRetry},
		{429, nil, outcomeRetry},
		{500, nil, outcomeRetry},
		{503, nil, outcomeRetry},
	}
	for _, tc := range cases {
		if got := classify(tc.status, tc.err); got != tc.want {
			t.Errorf("classify(%d, %v) = %d, want %d", tc.status, tc.err, got, tc.want)
		}
	}
}

func TestRetryBackoff(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{1, 4 * time.Second},
		{2, 8 * time.Second},
		{7, 256 * time.Second},
		{8, maxPostBackoff},
		{200, maxPostBackoff},
	}
	for _, tc := range cases {
		if got := retryBackoff(4*time.Second, tc.failures); got != tc.want {
			t.Errorf("retryBackoff(4s, %d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

type fakeReader struct{ infos []model.JailInfo }

func (f *fakeReader) GetJailInfos(context.Context) ([]model.JailInfo, error) { return f.infos, nil }

func (f *fakeReader) set(jail string, ips ...string) {
	f.infos = []model.JailInfo{{JailName: jail, BannedIPs: ips}}
}

type capturedPost struct {
	path, eventID, secret string
	body                  map[string]string
}

// Fake Fail2ban-UI answering with the scripted statuses, then 200.
type fakeUI struct {
	mu       sync.Mutex
	statuses []int
	posts    []capturedPost
}

func (u *fakeUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.posts = append(u.posts, capturedPost{r.URL.Path, r.Header.Get("X-Callback-Event-ID"), r.Header.Get("X-Callback-Secret"), body})
	status := http.StatusOK
	if len(u.statuses) > 0 {
		status, u.statuses = u.statuses[0], u.statuses[1:]
	}
	w.WriteHeader(status)
}

func (u *fakeUI) snapshot() []capturedPost {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]capturedPost(nil), u.posts...)
}

type pollerHarness struct {
	p      *Poller
	reader *fakeReader
	ui     *fakeUI
	root   string
	url    string
	clock  time.Time
}

func newPollerHarness(t *testing.T, statuses ...int) *pollerHarness {
	t.Helper()
	h := &pollerHarness{reader: &fakeReader{}, ui: &fakeUI{statuses: statuses}, root: t.TempDir()}
	ts := httptest.NewServer(h.ui)
	t.Cleanup(ts.Close)
	h.url = ts.URL
	h.clock = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	h.p = NewPoller(config.Config{ConfigRoot: h.root, CallbackPollInterval: 4 * time.Second}, h.reader, log.New(io.Discard, "", 0))
	h.p.now = func() time.Time { return h.clock }
	h.configure(t, "srv-1")
	return h
}

func (h *pollerHarness) configure(t *testing.T, serverID string) {
	t.Helper()
	if err := config.SaveCallbackRuntimeConfig(h.root, config.CallbackRuntimeConfig{
		ServerID: serverID, CallbackURL: h.url, CallbackSecret: "cb-secret-123", CallbackHost: "agent-host",
	}); err != nil {
		t.Fatal(err)
	}
}

func (h *pollerHarness) tick(advance time.Duration) {
	h.clock = h.clock.Add(advance)
	h.p.tick(context.Background())
}

func TestPollerRetriesWithSameEventID(t *testing.T) {
	h := newPollerHarness(t, http.StatusServiceUnavailable)
	h.reader.set("sshd")
	// baseline
	h.tick(0)
	h.reader.set("sshd", "203.0.113.7")
	h.tick(4 * time.Second)
	if st := h.p.Stats(); st.Pending != 1 || st.LastError == "" {
		t.Fatalf("503 must keep the event queued: %+v", st)
	}
	h.tick(4 * time.Second)

	posts := h.ui.snapshot()
	if len(posts) != 2 {
		t.Fatalf("posts = %d, want 2", len(posts))
	}
	if posts[0].eventID == "" || len(posts[0].eventID) != 32 || posts[0].eventID != posts[1].eventID {
		t.Fatalf("retry must reuse the event ID: %q vs %q", posts[0].eventID, posts[1].eventID)
	}
	p := posts[1]
	if p.path != "/api/ban" || p.secret != "cb-secret-123" || p.body["serverId"] != "srv-1" || p.body["ip"] != "203.0.113.7" || p.body["hostname"] != "agent-host" {
		t.Fatalf("unexpected post: %+v", p)
	}
	if st := h.p.Stats(); st.Pending != 0 || st.LastPostOK.IsZero() || st.LastError != "" {
		t.Fatalf("stats after delivery: %+v", st)
	}
}

func TestPollerStopsBatchOnRetryableStatusAndBacksOff(t *testing.T) {
	h := newPollerHarness(t, http.StatusTooManyRequests, http.StatusTooManyRequests)
	h.reader.set("sshd")
	h.tick(0)
	h.reader.set("sshd", "192.0.2.1", "192.0.2.2")
	h.tick(4 * time.Second)
	if n := len(h.ui.snapshot()); n != 1 {
		t.Fatalf("batch must stop at the first retryable failure, posts = %d", n)
	}
	// failures=1: backoff 4s elapsed
	h.tick(4 * time.Second)
	// failures=2: backoff 8s not yet elapsed
	h.tick(4 * time.Second)
	if n := len(h.ui.snapshot()); n != 2 {
		t.Fatalf("backoff not honoured, posts = %d", n)
	}
	h.tick(4 * time.Second)
	var order []string
	for _, p := range h.ui.snapshot() {
		order = append(order, p.body["ip"])
	}
	want := []string{"192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.2"}
	if st := h.p.Stats(); !reflect.DeepEqual(order, want) || st.Pending != 0 {
		t.Fatalf("queue not drained in order after backoff: posts=%v %+v", order, st)
	}
}

func TestPollerDropsRejectedEvents(t *testing.T) {
	h := newPollerHarness(t, http.StatusBadRequest)
	h.reader.set("sshd")
	h.tick(0)
	h.reader.set("sshd", "192.0.2.1", "192.0.2.2")
	h.tick(4 * time.Second)
	if st := h.p.Stats(); st.Rejected != 1 || st.Pending != 0 || len(h.ui.snapshot()) != 2 {
		t.Fatalf("400 must drop only that event: posts=%d %+v", len(h.ui.snapshot()), st)
	}
}

func TestPollerResetsWhenUnconfigured(t *testing.T) {
	h := newPollerHarness(t, http.StatusServiceUnavailable)
	h.reader.set("sshd")
	h.tick(0)
	h.reader.set("sshd", "192.0.2.1")
	h.tick(4 * time.Second)
	if err := os.Remove(config.CallbackConfigPath(h.root)); err != nil {
		t.Fatal(err)
	}
	h.tick(4 * time.Second)
	if st := h.p.Stats(); st.Pending != 0 {
		t.Fatalf("queue kept after the callback was removed: %+v", st)
	}
	h.configure(t, "srv-1")
	h.reader.set("sshd", "192.0.2.1", "192.0.2.9")
	h.tick(4 * time.Second)
	if n := len(h.ui.snapshot()); n != 1 {
		t.Fatalf("re-configuration must start from a fresh baseline, posts = %d", n)
	}
}

func TestPollerPurgesEventsOfAnotherServer(t *testing.T) {
	h := newPollerHarness(t, http.StatusServiceUnavailable)
	h.reader.set("sshd")
	h.tick(0)
	h.reader.set("sshd", "192.0.2.1")
	h.tick(4 * time.Second)
	h.configure(t, "srv-2")
	h.tick(4 * time.Second)
	if st := h.p.Stats(); len(h.ui.snapshot()) != 1 || st.Pending != 0 {
		t.Fatalf("srv-1 events must be purged after switching to srv-2: posts=%d %+v", len(h.ui.snapshot()), st)
	}
}
