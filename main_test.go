package main

import (
	"os"
	"testing"

	dns "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a

	if len(zone) == 0 {
		zone = "sysblz.com."
	}
	fixture := dns.NewFixture(&dnspodSolver{},
		dns.SetDNSName(zone),
		dns.SetResolvedZone(zone),
		dns.SetDNSServer("1.1.1.1:53"),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/dnspod"),
		// dns.SetBinariesPath("_test/kubebuilder/bin"),
	)

	fixture.RunConformance(t)
}
