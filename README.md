## Introduction

The Shodan.NET class library provides a WebAPI class to Search() and GetHost()-information. It currently relies .NET 4.0 and help is welcome for making it compatible with earlier .NET releases.

## Usage

Before you can use the API, you need to have an API key.

[Get your API key here](http://www.shodanhq.com/api_doc)

Setup the SHODAN WebAPI:

	using Shodan;
	
	WebAPI api = new WebAPI("YOUR KEY");

Print a list of cisco-ios devices:

	SearchResult results = api.Search("cisco-ios");

    Console.WriteLine("Total: " + results.NumResults);
    foreach (Host h in results.Hosts)
    {
        Console.WriteLine(h.IP.ToString());
    }

Get all the information SHODAN has on the IP 217.140.75.46:

	Host host = api.GetHost("217.140.75.46");
	Console.WriteLine(host.IP.ToString());
