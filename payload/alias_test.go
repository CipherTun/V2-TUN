package payload

import "testing"

func TestSSHWSTCPAlias(t *testing.T) {
	ctx := Context{Host: "bug.example.com", Port: 22}
	want, err := CompileCompat("@ssh-ws")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"@ssh-ws/tcp", "@SSH-WS/TCP", " @ssh-ws/tcp "} {
		got, err := CompileCompat(name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if g, w := got.Preview(ctx), want.Preview(ctx); g != w {
			t.Fatalf("%q rendered %q, want %q", name, g, w)
		}
	}
}
