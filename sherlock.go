// Sherlock: Find Usernames Across Social Networks 

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const moduleName string = "Sherlock: Find Usernames Across Social Networks"
const version string = "0.14.0"

type probeBody struct {
	OperationName string `json:"operationName"`
	Query         string `json:"query"`
	Username      string `json:"string"`
	Variables     map[string]string `json:"variables"`
}

type siteRecord struct {
	MainURL           string `json:"urlMain"`
	UserURL           string `json:"url"`
	ProbeURL          string `json:"urlProbe"`
	ProbeMethod       string `json:"request_method"`
	ProbeHeader       map[string]string `json:"headers"`
	ProbeBody         probeBody `json:"request_payload"`
	ErrorMessage      json.RawMessage `json:"errorMsg"`
	ErrorType         string `json:"errorType"`
	UsernameFormat    string `json:"regexCheck"`
	ClaimedUsername   string `json:"username_claimed"`
	UnclaimedUsername string `json:"username_unclaimed"`
}

type siteSearchResults struct {
	SiteName       string
	CheckedURL     string
	UsernameStatus string
	ResponseTime   float64
}

// Concurrency management
var requestTokens = make(chan struct{}, 5)  
var wg sync.WaitGroup
var m sync.Mutex
var sherlockResults []siteSearchResults
func addToSherlockResults(sr siteSearchResults) {
	m.Lock()
	sherlockResults = append(sherlockResults, sr)
	m.Unlock()
}


func sherlock(username string, 
              allSiteData map[string]siteRecord,
              useUniqueTor bool,
              timeout float64,
              printAll bool,
              verbose bool) {
	// Checks for existence of username on various social media sites.
	// 
	// Arguments:
	// username     -- String indicating username that report
	//                 should be created against.
	// allSiteData  -- Map containing all of the site data.
	// useTor       -- Boolean indicating whether to use a tor circuit for the requests.
	// useUniqueTor -- Boolean indicating whether to use a new tor circuit for each request.
	// timeout      -- Time in seconds to wait before timing out request.
	//                 Default is no timeout.
	//
	// Return Values:
	// Map containing results of all site analyses.
	//  - Key:   Site name
	//  - Value: siteSearchResults struct

	// Notify caller that we are starting the query.
	fmt.Printf("Checking for username: %s\n", username)

	for site, siteInfo := range allSiteData {
		wg.Add(1)
		go probeSite(username, site, siteInfo, timeout, useUniqueTor, printAll, verbose)
	}

	wg.Wait()
}


func probeSite(username string, site string, siteInfo siteRecord,
               timeout float64, useUniqueTor bool, printAll bool, verbose bool) {
	defer wg.Done()
	var siteResults siteSearchResults
	siteResults.SiteName = site

	// Check if the site has guidelines for usernames
	var re *regexp.Regexp = nil
	var err error
	if len(siteInfo.UsernameFormat) > 0 {
		re, err = regexp.Compile(siteInfo.UsernameFormat)
		if err != nil {
			if verbose {
				fmt.Printf("[!] %s: Error when compiling regexp \"%s\": %v\n", site, siteInfo.UsernameFormat, err)
			}
		} else if re.MatchString(username) == false {
			// No need check this site since the username is invalid
			siteResults.CheckedURL = ""
			siteResults.UsernameStatus = "Illegal"
			siteResults.ResponseTime = -1.0
			addToSherlockResults(siteResults)
			return
		}
	}

	// -------------------
	// SET UP HTTP REQUEST
	// -------------------

	requestMethod := "GET"
	if len(siteInfo.ProbeMethod) > 0 {
		requestMethod = siteInfo.ProbeMethod
	}

	// Determine which URL to probe
	var checkURL string
	if len(siteInfo.ProbeURL) > 0 {
		// There is a special URL to check in order to find users
		// that is different from the normal user profile URL.
		checkURL = strings.Replace(siteInfo.ProbeURL, "{}", username, -1)
	} else {
		checkURL = strings.Replace(siteInfo.UserURL, "{}", username, -1)
	}
	siteResults.CheckedURL = checkURL
	
	var requestBody io.Reader = nil
	if len(siteInfo.ProbeBody.Query) > 0 && len(siteInfo.ProbeBody.Variables) > 0 {
		// Substitute for variables in the query embedded in the request body
		query := siteInfo.ProbeBody.Query
		for variable, _ := range siteInfo.ProbeBody.Variables {
			originalStr := "(" + variable + ":"
			replaceStr := "(" + username + ":"
			query = strings.Replace(query, originalStr, replaceStr, 1)
		}
		if verbose {
			fmt.Printf("[$] Query for %s: %s\n", site, query)
		}
		requestBody = strings.NewReader(query)
	}
	
	req, err := http.NewRequest(requestMethod, checkURL, requestBody)
	if err != nil {
		if verbose {
			fmt.Printf("[!] %s: Error when creating new HTTP request: %v\n", site, err)
		}
		addToSherlockResults(siteResults)
		return
	}
	req.Close = true

	// Without user agent, sites will consider requests as bot activity,
	// and we will be unable to obtain correct information.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0")
	for key, value := range siteInfo.ProbeHeader {
		req.Header.Set(key, value)
	}

	// ------------------
	// SET UP HTTP CLIENT
	// ------------------

	client := http.Client{}
	if timeout > 0.0 {
		client.Timeout = time.Duration(timeout * float64(time.Second))
	}

	// Disallow redirects if the error sought is the response URL
	// so the http status from original URL request can be captured
	if siteInfo.ErrorType == "response_url" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// ---------------
	// EXECUTE REQUEST
	// ---------------

	requestTokens <- struct{}{}
	t0 := time.Now()
	resp, err := client.Do(req)
	t1 := time.Now()
	<-requestTokens

	// ----------------
	// EXAMINE RESPONSE
	// ----------------

	siteResults.ResponseTime = t1.Sub(t0).Seconds()

	if err != nil {
		if verbose {
			if os.IsTimeout(err) {
				fmt.Printf("[!] %s: Timed out.\n", site)
			} else {
				fmt.Printf("[!] %s: Error when executing HTTP request: %v\n", site, err)
			}
		}
		siteResults.UsernameStatus = "Unknown"
	} else {
		switch siteInfo.ErrorType {
		case "status_code":
			// TODO: Each site has its own ErrorCode?
			//if resp.StatusCode == siteInfo.ErrorCode {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				siteResults.UsernameStatus = "Claimed"
			} else {
				siteResults.UsernameStatus = "Available"
			}
		case "message":
			// Convert response body to string
			bodyBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				if verbose {
					fmt.Printf("[!] Error when reading response body: %v\n", site, err)
				}
				siteResults.UsernameStatus = "Unknown"
			} else {
				bodyStr := string(bodyBytes)
				var errorMessageFormats []string
				switch siteInfo.ErrorMessage[0] {
				case '"':
					var errorMessageFormat string
					if err = json.Unmarshal(siteInfo.ErrorMessage, &errorMessageFormat); err != nil {
						if verbose {
							fmt.Printf("[!] %s: Error when unmarshaling JSON: %v\n", site, err)
						}
					} else {
						errorMessageFormats = append(errorMessageFormats, errorMessageFormat)
					}
				case '[':
					err = json.Unmarshal(siteInfo.ErrorMessage, &errorMessageFormats)
					if err != nil {
						fmt.Printf("[!] %s: Error when unmarshaling JSON: %v\n", site, err)
					}
				}
				if len(errorMessageFormats) == 0 {
					siteResults.UsernameStatus = "Unknown"
				} else {
					errorsWereFound := false
					for _, msg := range errorMessageFormats {
						if (strings.Contains(bodyStr, msg)) {
							errorsWereFound = true
							break
						}
					}
					if errorsWereFound {
						siteResults.UsernameStatus = "Available"
					} else {
						siteResults.UsernameStatus = "Claimed"
					}
				}
			}
		case "response_url":
			// For this detection method, redirects are disabled,
			// so there is no need to check the response URL
			// since it will always match the request.
			// Instead, we will ensure that the response code
			// indicates that the request was successful
			// (i.e. no 404 or forward to an odd redirect).
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				siteResults.UsernameStatus = "Claimed"
			} else {
				siteResults.UsernameStatus = "Available"
			}
		}
	}

	addToSherlockResults(siteResults)
	printSiteResults(&siteResults, printAll)
}


func printSiteResults(sr *siteSearchResults, printAll bool) {
	if sr.UsernameStatus == "Claimed" {
		fmt.Printf("[o] %s: %s\n", sr.SiteName, sr.CheckedURL)
	} else if printAll && sr.UsernameStatus != "Claimed" {
		fmt.Printf("[x] %s: User not found\n", sr.SiteName)
	}
}


func getCurrentSherlockVersion() string {
	currentVersion := ""
	
	// Download the latest version from GitHub
	// and extract its version string
	resp, err := http.Get("https://raw.githubusercontent.com/jstlwy/sherlock_go/master/sherlock.go")
	defer resp.Body.Close()
	if err != nil {
		fmt.Printf("Error when making HTTP request: %v\n", err)
	} else {
		scanner := bufio.NewScanner(resp.Body)
		if scanErr := scanner.Err(); scanErr != nil {
			fmt.Printf("Error when scanning HTTP response body: %v\n", scanErr)
		} else {
			re := regexp.MustCompile(`const version string = "(\d+\.\d+\.\d+)"`)
			for scanner.Scan() {
				currentLine := scanner.Text()
				matches := re.FindStringSubmatch(currentLine)
				if matches != nil {
					currentVersion = matches[1]
					break
				}
			}
		}
	}

	return currentVersion
}


func main() {
	// ------------
	// SET UP FLAGS
	// ------------

	displayVersion := flag.Bool("version", false, "Display version information and dependencies.")
	verbose        := flag.Bool("verbose", false, "Display extra debugging information and metrics.")
	//noColor        := flag.Bool("no-color", false, "Don't add color to the terminal output.")
	usernameArg    := flag.String("username", "",
		"The username(s) to search for on each social network. " + 
		"To specify multiple usernames, separate each with a comma.")
	jsonFilePath   := flag.String("json", "",
		"User-specified JSON file from which to load site data.")
	outputDir      := flag.String("outdir", "",
		"The directory to which to save the results for multiple usernames.")
	outputFile     := flag.String("outfile", "",
		"The file to which to save the results for a single username.")
	numConnections := flag.Int("connections", 10,
		"The max number of concurrent connections to allow.")
	timeout        := flag.Float64("timeout", 0.0,
		"Time (in seconds) to wait for responses to requests. " +
		"Default timeout is infinity. " +
		"With a longer timeout, Sherlock will be more likely to get results from slow sites. " +
		"On the other hand, this may cause the program to take longer to complete.")
	proxy          := flag.String("proxy", "",
		"Specify a proxy over which to make requests, e.g. socks5://127.0.0.1:1080")
	useTor         := flag.Bool("tor", false,
		"Make requests over Tor. Increases runtime. " + 
		"requires Tor to be installed and in system path.")
	useUniqueTor   := flag.Bool("uniquetor", false,
		"Make requests over Tor with new Tor circuit after each request. " +
		"Increases runtime. Requires Tor to be installed and in system path.")
	saveToCSV      := flag.Bool("csv", false, "Create Comma-Separated Values (CSV) file.")
	printAll       := flag.Bool("all", false,
		"Output all results, including those where the username was not found.")
	siteList       := flag.String("site", "",
		"Limit analysis to just the listed sites. " +
		"Must be the site name as shown in the JSON list, not a URL. " +
		"Separate multiple sites with commas.")
	flag.Parse()

	if *displayVersion {
		fmt.Printf("%s\n%s\n", moduleName, version)
		// Check if using latest version
		currentVersion := getCurrentSherlockVersion()
		if currentVersion != "" && currentVersion != version {
			fmt.Printf("Version %s available at: https://github.com/sherlock-project/sherlock\n", currentVersion)
		}
		os.Exit(0)
	}
	
	requestTokens = make(chan struct{}, *numConnections)
	
	// -----------------------------
	// CHECK FOR INVALID FLAG VALUES
	// -----------------------------

	if *timeout < 0.0 {
		fmt.Println("Error: Invalid timeout value.")
		os.Exit(1)
	}

	if *useTor && len(*proxy) > 0 {
		fmt.Println("Error: Tor and proxies cannot used simultaneously.")
		os.Exit(1)
	}
	
	// TODO: Validate proxy address
	if len(*proxy) > 0 {
		fmt.Printf("Using proxy: %s\n" + *proxy)
		os.Setenv("HTTP_PROXY", *proxy)
	}

	if *useTor || *useUniqueTor {
		fmt.Println("Using Tor to make requests.")
		fmt.Println("Warning: Some websites might refuse connections via Tor.")
	}

	// Check if user specified both an output file and an output directory
	if len(*outputFile) > 0 && len(*outputDir) > 0 {
		fmt.Println("Error: You can specify either an output file or an output directory, but not both.")
		os.Exit(1)
	}

	// Check if user failed to provide any usernames
	if len(*usernameArg) == 0 {
		fmt.Println("Error: No username was provided.")
		os.Exit(1)
	}

	passedUsernames := strings.Split(*usernameArg, ",")
	
	// Check if user provided more than one username
	// but also specified an output file
	if len(*outputFile) > 0 && len(passedUsernames) > 1 {
		fmt.Println("Error: -outfile can only be used when searching for a single username.")
		os.Exit(1)
	}

	// Don't keep any empty usernames
	var usernames []string
	for _, uname := range passedUsernames {
		if len(uname) > 0 {
			usernames = append(usernames, uname)
		}
	}

	// Quit if no valid usernames were passed to the program
	if len(usernames) == 0 {
		fmt.Println("Error: No valid usernames were found.")
		os.Exit(1)
	}

	// Load JSON file
	var rawJSON []byte
	var err error
	if len(*jsonFilePath) == 0 {
		rawJSON, err = os.ReadFile("resources/data.json")
	} else {
		rawJSON, err = os.ReadFile(*jsonFilePath)
	}
	if err != nil {
		fmt.Printf("Error when reading JSON file: %v\n", err)
		os.Exit(1)
	}

	// Unmarshal JSON into a map
	allSiteData := make(map[string]siteRecord)
	err = json.Unmarshal(rawJSON, &allSiteData) 
	if err != nil {
		fmt.Printf("Error when unmarshaling JSON: %v\n", err)
		os.Exit(1)
	}

	// Check if user specified which sites to check.
	// If so, remove all others from the allSiteData map.
	if len(*siteList) > 0 {
		userSpecifiedSites := strings.Split(*siteList, ",")
		userSpecifiedSiteData := make(map[string]siteRecord)
		for _, userSite := range userSpecifiedSites {
			if len(userSite) == 0 {
				continue
			}
			for site, data := range allSiteData {
				if strings.ToLower(userSite) == strings.ToLower(site) {
					userSpecifiedSiteData[site] = data
					break
				}
			}
		}
		if len(userSpecifiedSiteData) > 0 {
			allSiteData = userSpecifiedSiteData
		}
	}

	// If searching for multiple usernames,
	// make sure an output directory name exists.
	outputDirName := *outputDir
	if len(usernames) > 1 {
		if len(outputDirName) == 0 {
			currentTime := time.Now()
			currentTime.Format("2006-01-02_15:04:05")		
			outputDirName = "sherlock_results_" + currentTime.String()
		}
	}
	// Create the output directory if necessary
	if len(outputDirName) > 0 {
		err = os.Mkdir(outputDirName, 0750)
		if err != nil && !os.IsExist(err) {
			fmt.Printf("Error when creating directory \"%s\": %v\n", outputDirName, err)
			os.Exit(1)
		}
		outputDirName += "/"
	}

	// --------------
	// EXECUTE SEARCH
	// --------------

	for _, username := range usernames {
		sherlockResults = nil
		sherlock(
			username,
			allSiteData,
			*useUniqueTor,
			*timeout,
			*printAll,
			*verbose,
		)

		var txtFilename string = *outputFile
		if len(txtFilename) == 0 {
			txtFilename = fmt.Sprintf("%s.txt", username)	
		}

		if _, err = os.Stat(outputDirName + txtFilename); err == nil {
			err = os.Remove(outputDirName + txtFilename)
			if err != nil {
				fmt.Printf("Error when attempting to remove existing file \"%s\": %v\n",
					outputDirName + txtFilename, err)
				continue
			}
		}

		txtFile, err := os.OpenFile(outputDirName + txtFilename, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Error when opening \"%s\": %v\n", outputDirName + txtFilename, err)
			continue
		}
		txtFile.WriteString("Web sites where username \"" + username + "\" was detected:\n\n")

		numSuccesses := 0
		for _, siteResults := range sherlockResults {
			if siteResults.UsernameStatus == "Claimed" {
				numSuccesses++
				txtFile.WriteString("Site name: " + siteResults.SiteName + "\n")
				txtFile.WriteString("Checked URL: " + siteResults.CheckedURL + "\n")
				queryTimeStr := fmt.Sprintf("%f", siteResults.ResponseTime)
				txtFile.WriteString("Response time (s): " + queryTimeStr + "\n\n")
			}
		}
		numSuccessesStr := fmt.Sprintf("%d", numSuccesses)
		txtFile.WriteString("Number of websites where username was detected: " + numSuccessesStr + "\n")
		txtFile.Close()

		if *saveToCSV {
			csvFilename := fmt.Sprintf("%s.csv", username)
			csvFile, err := os.OpenFile(outputDirName + csvFilename, os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				fmt.Printf("Error when opening \"%s\": %v\n", outputDirName + csvFilename, err)
				continue
			}

			writer := csv.NewWriter(csvFile)
			columnTitles := []string {
				"Site Name",
				"Checked URL",
				"Username Status",
				"Response Time (s)",
			}

			err = writer.Write(columnTitles)
			if err != nil {
				fmt.Printf("Error when writing to \"%s\": %v\n", outputDirName + csvFilename, err)
			}
			for _, siteResults := range sherlockResults {
				row := []string {
					siteResults.SiteName,
					siteResults.CheckedURL,
					siteResults.UsernameStatus,
					fmt.Sprintf("%f", siteResults.ResponseTime),
				}
				err = writer.Write(row)
				if err != nil {
					fmt.Printf("Error when writing to \"%s\": %v\n", outputDirName + csvFilename, err)
				}
				writer.Flush()
			}

			csvFile.Close()
		}

		fmt.Printf("Number of websites where username \"%s\" was detected: %d\n\n", username, numSuccesses)
	}
}

