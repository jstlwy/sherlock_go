# sherlock_go

An implementation of [Sherlock](https://github.com/sherlock-project/sherlock) in Go.

## Installation

```
# Clone the repo
$ git clone https://github.com/jstlwy/sherlock_go.git

# Change the working directory to sherlock_go
$ cd sherlock_go

# Build
$ go build sherlock.go
```

## Usage

```
$ ./sherlock -help
Usage of ./sherlock:
  -all
    	Output all results, including those where the username was not found.
  -connections int
    	The max number of concurrent connections to allow. (default 5)
  -csv
    	Create Comma-Separated Values (CSV) file.
  -json string
    	User-specified JSON file from which to load site data.
  -outdir string
    	The directory to which to save the results for multiple usernames.
  -outfile string
    	The file to which to save the results for a single username.
  -proxy string
    	Specify a proxy over which to make requests, e.g. socks5://127.0.0.1:1080
  -site string
    	Limit analysis to just the listed sites. Add multiple options to specify more than one site.
  -timeout float
    	Time (in seconds) to wait for responses to requests. Default timeout is infinity. With a longer timeout, Sherlock will be more likely to get results from slow sites. On the other hand, this may cause the program to take longer to complete.
  -tor
    	Make requests over Tor. Increases runtime. requires Tor to be installed and in system path.
  -uniquetor
    	Make requests over Tor with new Tor circuit after each request. Increases runtime. Requires Tor to be installed and in system path.
  -username string
    	The username(s) to search for on each social network. To specify multiple usernames, separate each with a comma.
  -verbose
    	Display extra debugging information and metrics.
  -version
    	Display version information and dependencies.
```

To search for only one user:
```
sherlock -username user123
```

To search for more than one user:
```
sherlock -username user1,user2,user3
```

Accounts found will be stored in a text file with a filename corresponding to the username (e.g `user123.txt`).

## Issues

Please be aware that this program is far from perfect.
I only made it because I wanted to get more practice with programming in Go, 
but I don't have any ideas of my own.

- Connections over Tor not yet supported
- Color output not yet implemented
- As the number of goroutines, which is controlled by the `-connections` flag, increases, so will the number of false negatives
- Go's `regexp` package does not support negative lookahead

## License

MIT © [Sherlock Project](https://github.com/sherlock-project)<br/>

Original Creator - [Siddharth Dushantha](https://github.com/sdushantha)
