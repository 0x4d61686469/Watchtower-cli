package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// Base API URL - change this if your backend runs elsewhere
const baseURL = "http://127.0.0.1:5000"

var allFlag bool

func main() {
	// Root Command: watchtower
	var rootCmd = &cobra.Command{
		Use:   "watchtower",
		Short: "Watchtower CLI client for rapid recon querying",
	}

	rootCmd.PersistentFlags().BoolVar(&allFlag, "all", false, "Append ?all query parameter to the request")

	// Subcommands (Categories)
	var dnsCmd = &cobra.Command{Use: "dns", Short: "Query DNS recon data"}
	var httpCmd = &cobra.Command{Use: "http", Short: "Query HTTP recon data"}
	var nucleiCmd = &cobra.Command{Use: "nuclei", Short: "Query Nuclei vulnerability scans"}
	var programCmd = &cobra.Command{Use: "programs", Short: "Query tracked programs"}
	var subdomainsCmd = &cobra.Command{Use: "subdomains", Short: "Query general subdomain data"}

	// --- analysis Actions ---
	// Make it a direct action command instead of an empty category wrapper
	var analysisCmd = &cobra.Command{
		Use:   "analysis", 
		Short: "Query analysis results by fetching /analyze",
		Run: func(cmd *cobra.Command, args []string) {
			makeRequest(withAllQuery(baseURL + "/analyze"))
		},
	}



	// --- DNS Actions ---
	dnsCmd.AddCommand(
		newQueryCmd("list_all", "/dns/all"),
		newQueryCmd("list_fresh", "/dns/fresh"),
		newParamQueryCmd("by_program [name]", "/dns/program/%s"),
		newParamQueryCmd("by_program_ips [name]", "/dns/program/%s/ips"),
		newParamQueryCmd("by_provider [name]", "/dns/provider/%s"),
		newParamQueryCmd("by_scope [scope]", "/dns/scope/%s"),
		newParamQueryCmd("by_scope_ips [scope]", "/dns/scope/%s/ips"),
		newParamQueryCmd("get_subdomain_info [subdomain]", "/dns/subdomain/%s"),
	)

	// --- HTTP Actions ---
	httpCmd.AddCommand(
		newQueryCmd("list_all", "/http/all"),
		newQueryCmd("list_fresh", "/http/fresh"),
		newQueryCmd("list_status_codes", "/http/status_code/all"),
		newQueryCmd("list_techs", "/http/tech/all"),
		newQueryCmd("list_titles", "/http/title/all"),
		newParamQueryCmd("by_program [name]", "/http/program/%s"),
		newParamQueryCmd("by_program_ips [name]", "/http/program/%s/ips"),
		newParamQueryCmd("by_provider [name]", "/http/provider/%s"),
		newParamQueryCmd("by_scope [scope]", "/http/scope/%s"),
		newParamQueryCmd("by_scope_ips [scope]", "/http/scope/%s/ips"),
		newParamQueryCmd("by_status_code [code]", "/http/status_code/%s"),
		newParamQueryCmd("by_tech [tech]", "/http/tech/%s"),
		newParamQueryCmd("by_title [title]", "/http/title/%s"),
		newParamQueryCmd("get_subdomain_info [subdomain]", "/http/subdomain/%s"),
		newParamQueryCmd("get_url_info [url]", "/http/url/%s"),
		newParamQueryCmd("search_headers [term]", "/http/headers/%s"),
	)

	// --- Nuclei Actions ---
	nucleiCmd.AddCommand(
		newQueryCmd("list_all", "/nuclei/all"),
		newParamQueryCmd("by_program [name]", "/nuclei/program/%s"),
		newParamQueryCmd("search [term]", "/nuclei/search/%s"),
	)

	// --- Program Actions ---
	programCmd.AddCommand(
		newQueryCmd("list_all", "/program/all"),
		newParamQueryCmd("get_by_name [name]", "/program/%s"),
	)

	// --- Subdomain Actions ---
	subdomainsCmd.AddCommand(
		newQueryCmd("list_all", "/subdomains/all"),
		newParamQueryCmd("by_program [name]", "/subdomains/program/%s"),
		newParamQueryCmd("by_scope [scope]", "/subdomains/scope/%s"),
		newParamQueryCmd("get_info [subdomain]", "/subdomains/%s"),
	)

	// Add all categories to root command
	rootCmd.AddCommand(dnsCmd, httpCmd, nucleiCmd, programCmd, subdomainsCmd, analysisCmd)

	// Execute CLI
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// Helper for static endpoints (e.g., /http/all)
func newQueryCmd(use, path string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: fmt.Sprintf("Fetch %s", path),
		Run: func(cmd *cobra.Command, args []string) {
			makeRequest(withAllQuery(baseURL + path))
		},
	}
}

// Helper for dynamic endpoints that require an argument (e.g., /http/tech/<tech>)
func newParamQueryCmd(use, pathTemplate string) *cobra.Command {
	return &cobra.Command{
		Use:   use, // Keep this strictly as the keyword (e.g., "search_headers")
		Short: fmt.Sprintf("Query backend via %s", pathTemplate), 
		Args:  cobra.ExactArgs(1), // This forces the terminal to require the 1 argument
		Run: func(cmd *cobra.Command, args []string) {
			url := fmt.Sprintf(baseURL+pathTemplate, args[0])
			makeRequest(withAllQuery(url))
		},
	}
}

func withAllQuery(url string) string {
	if allFlag {
		return url + "?all"
	}
	return url
}

// Reusable HTTP request logic
func makeRequest(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[!] Error connecting to backend: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[!] Error reading response: %v\n", err)
		return
	}

	// Prints raw JSON payload directly to terminal
	fmt.Println(string(body))
}