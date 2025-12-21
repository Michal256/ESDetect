package patterns

import "regexp"

var (
	// Matches standard Docker cgroups: /docker/<cid> or /system.slice/docker-<cid>.scope
	DockerCgroup = regexp.MustCompile(`(?:^|/)docker[-/](?P<cid>[0-9a-f]{12,64})(?:\.scope)?`)

	// Matches CRI-Containerd cgroups (common in K8s): .../cri-containerd-<cid>.scope
	CriCgroup = regexp.MustCompile(`cri-containerd-(?P<cid>[0-9a-f]{12,64})\.scope`)

	// Matches K8s cgroups (standard): /kubepods/.../pod<uid>/<cid>
	K8sCgroup = regexp.MustCompile(`/kubepods/(?:[^/]+/)?pod[0-9a-f\-_]{36}/(?P<cid>[0-9a-f]{64})`)
	PodUid    = regexp.MustCompile(`pod([0-9a-f\-_]{36})`)

	ExecveLog = regexp.MustCompile(`^EXECVE pid=(?P<pid>\d+)\s+cgroup_id=(?P<cid>\d+)\s+comm=(?P<comm>.*?)\s+filepath=(?P<filepath>.*?)\s+argv=(?P<argv>.*)$`)

	OpenLog = regexp.MustCompile(`^OPEN pid=(?P<pid>\d+)\s+cgroup_id=(?P<cid>\d+)\s+comm=(?P<comm>.*?)\s+filepath=(?P<filepath>.*)$`)
)
