//go:build linux

package nativesandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFixedProfileBinding(t *testing.T) {
	if ProfileDigest() == "" || ProfileDigest() != ProfileDigest() || len(ProfileDigest()) != 71 {
		t.Fatal("invalid profile digest")
	}
	if _, e := New(Tool{}); !errors.Is(e, ErrTool) {
		t.Fatal(e)
	}
	var r *Runner
	if r.Binding() != (Binding{}) {
		t.Fatal("nil binding")
	}
	for _, s := range []Spec{{}, {LoaderPath: "../../bin/sh", NginxPath: "bin/nginx"}, {LoaderPath: "lib/ld-linux-x86-64.so.2", NginxPath: "bin/sh"}} {
		if e := r.RunNginx(context.Background(), s); !errors.Is(e, ErrInput) {
			t.Fatal(e)
		}
	}
}
func TestSealedSnapshot(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(dir, "nginx.conf")
	if e := os.WriteFile(name, []byte("original"), 0400); e != nil {
		t.Fatal(e)
	}
	s, e := capture(context.Background(), dir, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if len(s.entries) != 1 {
		t.Fatal("bad entries")
	}
	m := s.entries[0].file
	if _, e = unix.Write(int(m.Fd()), []byte("tamper")); !errors.Is(e, unix.EPERM) {
		t.Fatal("snapshot mutable", e)
	}
	if e = os.Chmod(name, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(name, []byte("changed!"), 0400); e != nil {
		t.Fatal(e)
	}
	if e = s.verify(context.Background()); !errors.Is(e, ErrInput) {
		t.Fatal("source drift accepted", e)
	}
	b := make([]byte, 8)
	if _, e = m.ReadAt(b, 0); e != nil || string(b) != "original" {
		t.Fatal("snapshot changed", e)
	}
}
func TestSnapshotRejectsUnsafeInputs(t *testing.T) {
	for _, kind := range []string{"symlink", "writable", "hardlink", "fifo", "directory-mode", "file-too-large"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			f := filepath.Join(dir, "nginx.conf")
			switch kind {
			case "symlink":
				os.Symlink("/etc/passwd", f)
			case "writable":
				os.WriteFile(f, []byte("x"), 0600)
			case "hardlink":
				os.WriteFile(f, []byte("x"), 0400)
				os.Link(f, filepath.Join(dir, "duplicate"))
			case "fifo":
				unix.Mkfifo(f, 0400)
			case "directory-mode":
				os.Mkdir(f, 0755)
			case "file-too-large":
				h, e := os.OpenFile(f, os.O_CREATE|os.O_WRONLY, 0400)
				if e != nil {
					t.Fatal(e)
				}
				h.Truncate((4 << 20) + 1)
				h.Close()
			}
			s, e := capture(context.Background(), dir, true)
			if s != nil {
				s.close()
			}
			if !errors.Is(e, ErrInput) {
				t.Fatal("unsafe input accepted", e)
			}
		})
	}
}

func TestSnapshotDescriptorCleanup(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte("input"), 0400)
	before, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		s, e := capture(context.Background(), dir, true)
		if e != nil {
			t.Fatal(e)
		}
		s.close()
	}
	after, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	if len(after) > len(before) {
		t.Fatalf("descriptor leak: %d -> %d", len(before), len(after))
	}
}

// Every native case is a fresh dedicated process; setting rlimits never changes
// a test server or the long-lived parent, and no privileged fixture is installed.
func TestNativeSandbox(t *testing.T) {
	if os.Getenv("AGP_TEST_BWRAP_BIN") == "" {
		if os.Getenv("AGP_TEST_NATIVE_REQUIRED") == "1" {
			t.Fatal("AGP_TEST_BWRAP_BIN is required")
		}
		t.Skip("explicit bubblewrap installation required")
	}
	if os.Getenv("AGP_SANDBOX_CHILD") == "1" {
		nativeChild(t)
		return
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	source := filepath.Join(dir, "probe.go")
	if e := os.WriteFile(source, []byte(probeSource), 0600); e != nil {
		t.Fatal(e)
	}
	probe := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", probe, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build probe: %v %s", e, b)
	}
	for _, name := range []string{"isolation", "timeout-descendant", "output-descendant", "normal-descendant", "tool-rejected", "input-rejected", "resource-limits", "snapshot-drift"} {
		t.Run(name, func(t *testing.T) {
			c := exec.Command(os.Args[0], "-test.run=^TestNativeSandbox$", "-test.v")
			c.Env = append(os.Environ(), "AGP_SANDBOX_CHILD=1", "AGP_SANDBOX_CASE="+name, "AGP_SANDBOX_PROBE="+probe)
			b, e := c.CombinedOutput()
			if e != nil {
				t.Fatalf("native case %s: %v\n%s", name, e, b)
			}
		})
	}
}
func nativeChild(t *testing.T) {
	if os.Getenv("AGP_SANDBOX_CASE") == "resource-limits" {
		var lim unix.Rlimit
		if unix.Getrlimit(unix.RLIMIT_NOFILE, &lim) != nil {
			t.Fatal("getrlimit")
		}
		lim.Cur = 1025
		lim.Max = max(lim.Max, 1025)
		if unix.Setrlimit(unix.RLIMIT_NOFILE, &lim) != nil {
			t.Fatal("resource test requires parent NOFILE>=1025")
		}
		if e := CheckLimits(); !errors.Is(e, ErrUnavailable) {
			t.Fatal("unbounded process accepted", e)
		}
		return
	}
	if e := ApplyLocalProcessLimits(); e != nil {
		t.Fatal(e)
	}
	r, e := New(Tool{os.Getenv("AGP_TEST_BWRAP_BIN"), os.Getenv("AGP_TEST_BWRAP_DIGEST")})
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	runtimeDir := filepath.Join(dir, "runtime")
	configDir := filepath.Join(dir, "config")
	for _, p := range []string{runtimeDir, filepath.Join(runtimeDir, "lib"), filepath.Join(runtimeDir, "bin"), configDir} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	probe, e := os.ReadFile(os.Getenv("AGP_SANDBOX_PROBE"))
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"lib/ld-linux-x86-64.so.2", "bin/nginx"} {
		if e = os.WriteFile(filepath.Join(runtimeDir, p), probe, 0500); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(configDir, "nginx.conf"), []byte("synthetic"), 0400); e != nil {
		t.Fatal(e)
	}
	spec := Spec{runtimeDir, configDir, "lib/ld-linux-x86-64.so.2", "bin/nginx"}
	switch os.Getenv("AGP_SANDBOX_CASE") {
	case "tool-rejected":
		bad := r.tool
		bad.Digest = "sha256:" + strings.Repeat("0", 64)
		if _, e = New(bad); !errors.Is(e, ErrTool) {
			t.Fatal(e)
		}
		bad.Path = filepath.Join(dir, "missing")
		if _, e = New(bad); !errors.Is(e, ErrTool) {
			t.Fatal(e)
		}
		bad.Path = filepath.Join(dir, "unsafe-tool")
		raw, e := os.ReadFile(r.tool.Path)
		if e != nil {
			t.Fatal(e)
		}
		os.WriteFile(bad.Path, raw, 0755)
		h := sha256.Sum256(raw)
		bad.Digest = "sha256:" + hex.EncodeToString(h[:])
		if _, e = New(bad); !errors.Is(e, ErrTool) {
			t.Fatal("user-owned tool accepted", e)
		}
		return
	case "input-rejected":
		os.Chmod(filepath.Join(configDir, "nginx.conf"), 0600)
		if e = r.RunNginx(context.Background(), spec); !errors.Is(e, ErrInput) {
			t.Fatal(e)
		}
		return
	case "snapshot-drift":
		f := filepath.Join(configDir, "nginx.conf")
		go func() {
			time.Sleep(200 * time.Millisecond)
			os.Chmod(f, 0600)
			os.WriteFile(f, []byte("changed"), 0400)
		}()
		if e = r.run(context.Background(), spec, []string{"/runtime/bin/nginx", "delay"}); !errors.Is(e, ErrInput) {
			t.Fatal("concurrent source drift accepted", e)
		}
		return
	case "isolation":
		sentinel := filepath.Join(dir, "HOST_SENTINEL")
		os.WriteFile(sentinel, []byte("secret"), 0600)
		tcp, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer tcp.Close()
		sock := filepath.Join("/tmp", "agp-ns-"+filepath.Base(dir)+".sock")
		defer os.Remove(sock)
		us, e := net.Listen("unix", sock)
		if e != nil {
			t.Fatal(e)
		}
		defer us.Close()
		abstract, e := net.Listen("unix", "@agp-native-isolation-"+filepath.Base(dir))
		if e != nil {
			t.Fatal(e)
		}
		defer abstract.Close()
		if e = r.run(context.Background(), spec, []string{"/runtime/bin/nginx", "isolation", sentinel, tcp.Addr().String(), sock, abstract.Addr().String()}); e != nil {
			t.Fatal(e)
		}
	case "timeout-descendant", "output-descendant", "normal-descendant":
		kind := os.Getenv("AGP_SANDBOX_CASE")
		marker := filepath.Join(dir, "escaped.sock")
		// A descendant tries a host abstract UNIX socket after the caller returns;
		// the PID namespace must kill it even after setsid and inherited-pipe close.
		listener, e := net.Listen("unix", "@agp-native-"+filepath.Base(dir))
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		stopWatch, observed := watchDescendants(os.Getpid())
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		e = r.run(ctx, spec, []string{"/runtime/bin/nginx", kind, listener.Addr().String(), marker})
		close(stopWatch)
		seen := <-observed
		if len(seen) < 4 {
			t.Fatalf("insufficient descendant evidence: %d", len(seen))
		}
		for pid, pin := range seen {
			deadline := time.Now().Add(2 * time.Second)
			for {
				b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil || processIncarnation(b) != pin {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("descendant survived: %d", pid)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		switch kind {
		case "timeout-descendant":
			if !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal(e)
			}
		case "output-descendant":
			if !errors.Is(e, ErrOutput) {
				t.Fatal(e)
			}
		case "normal-descendant":
			if e != nil {
				t.Fatal(e)
			}
		}
		listener.(*net.UnixListener).SetDeadline(time.Now().Add(1200 * time.Millisecond))
		c, err := listener.Accept()
		if c != nil {
			c.Close()
			t.Fatal("descendant reached host")
		}
		if err == nil {
			t.Fatal("unexpected accept")
		}
	}
}

// Track the entire host PID subtree, including children forked from Go worker
// threads. This is independent evidence of PID-namespace teardown; network
// isolation alone cannot prove that detached descendants were killed.
func processIncarnation(b []byte) string {
	text := string(b)
	i := strings.LastIndex(text, ") ")
	if i < 0 {
		return ""
	}
	f := strings.Fields(text[i+2:])
	if len(f) < 20 || f[0] == "Z" {
		return ""
	}
	return f[19]
}
func watchDescendants(root int) (chan struct{}, chan map[int]string) {
	stop := make(chan struct{})
	result := make(chan map[int]string, 1)
	go func() {
		seen := make(map[int]string)
		var scan func(int)
		scan = func(pid int) {
			tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
			for _, task := range tasks {
				b, _ := os.ReadFile(task)
				for _, id := range strings.Fields(string(b)) {
					child, e := strconv.Atoi(id)
					if e != nil {
						continue
					}
					if _, ok := seen[child]; !ok {
						st, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child))
						if e == nil {
							seen[child] = processIncarnation(st)
						}
					}
					scan(child)
				}
			}
		}
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			scan(root)
			select {
			case <-stop:
				result <- seen
				return
			case <-ticker.C:
			}
		}
	}()
	return stop, result
}

const probeSource = `package main
import("fmt";"net";"os";"os/exec";"strconv";"strings";"syscall";"time")
func fail(s string){fmt.Fprintln(os.Stderr,s);os.Exit(23)}
func main(){
 if len(os.Args)<2{fail("case")};kind:=os.Args[1]
 if kind=="root-identity"{
  uid,e:=strconv.Atoi(os.Args[2]);if e!=nil||uid==0||os.Getuid()!=uid||os.Geteuid()!=uid{fail("execution UID")}
  gid,e:=strconv.Atoi(os.Args[3]);if e!=nil||gid==0||os.Getgid()!=gid||os.Getegid()!=gid{fail("execution GID")}
  groups,e:=os.Getgroups();if e!=nil||len(groups)!=0{fail("supplementary groups")}
  b,e:=os.ReadFile("/config/nginx.conf");if e!=nil||string(b)!="root-owned-private-input"{fail("root input unavailable after drop")}
  status,e:=os.ReadFile("/proc/self/status");if e!=nil{fail("status")};text:=string(status)
  for _,field:=range []string{"CapEff","CapPrm","CapInh","CapAmb"}{if !strings.Contains(text,field+":\t0000000000000000"){fail("capabilities retained")}}
  if !strings.Contains(text,"NoNewPrivs:\t1"){fail("new privileges allowed")};return
 }
 if kind=="descendant"{syscall.Close(0);syscall.Close(1);syscall.Close(2);time.Sleep(900*time.Millisecond);c,e:=net.DialTimeout("unix",os.Args[2],time.Second);if e==nil{c.Close()};for{time.Sleep(time.Second)}}
 if strings.HasSuffix(kind,"descendant"){
  c:=exec.Command("/runtime/bin/nginx","descendant",os.Args[2]);c.SysProcAttr=&syscall.SysProcAttr{Setsid:true};if c.Start()!=nil{fail("spawn")}
  if kind=="normal-descendant"{time.Sleep(300*time.Millisecond);return};if kind=="output-descendant"{time.Sleep(300*time.Millisecond);for{fmt.Print(strings.Repeat("x",8192))}};for{time.Sleep(time.Second)}
 }
 if kind=="delay"{time.Sleep(500*time.Millisecond);return}
 if kind!="isolation"{fail("unknown")}
 for _,p:=range []string{os.Args[2],"/etc/passwd","/home","/tmp"}{if _,e:=os.Stat(p);e==nil{fail("host filesystem visible")}}
 if _,e:=os.ReadFile("/launcher-pin");e==nil{fail("launcher pin readable")}
 for _,p:=range []string{"/config/nginx.conf","/runtime/bin/nginx"}{f,e:=os.OpenFile(p,os.O_WRONLY|os.O_TRUNC,0);if e==nil{f.Close();fail("input writable")}}
 for _,p:=range []string{"/dev/owned","/dev/shm/owned","/dev/pts/owned"}{if os.WriteFile(p,[]byte("x"),0600)==nil{fail("dev writable")}}
 if os.WriteFile("/config/new",[]byte("x"),0600)==nil||os.WriteFile("/new",[]byte("x"),0600)==nil{fail("root writable")}
 if os.WriteFile("/scratch/ok",[]byte("x"),0600)!=nil{fail("scratch unwritable")}
 var fs syscall.Statfs_t;if syscall.Statfs("/scratch",&fs)!=nil||fs.Type!=0x01021994||fs.Blocks*uint64(fs.Bsize)>64<<20{fail("scratch unbounded")}
 if c,e:=net.DialTimeout("tcp",os.Args[3],100*time.Millisecond);e==nil{c.Close();fail("host tcp reachable")}
 if c,e:=net.DialTimeout("unix",os.Args[4],100*time.Millisecond);e==nil{c.Close();fail("host unix reachable")}
 if c,e:=net.DialTimeout("unix",os.Args[5],100*time.Millisecond);e==nil{c.Close();fail("host abstract unix reachable")}
 status,e:=os.ReadFile("/proc/self/status");if e!=nil{fail("status")};text:=string(status)
 if !strings.Contains(text,"CapEff:\t0000000000000000")||!strings.Contains(text,"NoNewPrivs:\t1"){fail("privileges")}
 proc,e:=os.ReadDir("/proc");if e!=nil{fail("proc")};n:=0;for _,d:=range proc{if _,e=strconv.Atoi(d.Name());e==nil{n++}};if n>4{fail("host pid visible")}
 if syscall.Unshare(syscall.CLONE_NEWUSER)==nil{fail("nested userns permitted")}
 if syscall.Mount("tmpfs","/scratch","tmpfs",0,"")==nil{fail("mount permitted")}
 fds,e:=os.ReadDir("/proc/self/fd");if e!=nil{fail("fd list")};for _,d:=range fds{n,_:=strconv.Atoi(d.Name());if n<=2{continue};v,_:=os.Readlink("/proc/self/fd/"+d.Name());if strings.Contains(v,"memfd:")||strings.Contains(v,"bwrap")||strings.Contains(v,"sandbox-source"){fail("inherited host fd")}}
}`
