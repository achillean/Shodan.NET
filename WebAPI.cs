using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
using System.Globalization;

namespace Shodan
{
    public class WebAPI
    {
        private readonly string API_KEY;
        private const string BASE_URL = "http://beta.shodanhq.com/api/";
        private JavaScriptSerializer json_parser = new JavaScriptSerializer();
        private WebClient web_client = new WebClient();

        /// <summary>
        /// Initialize the Shodan WebAPI object.
        /// </summary>
        /// <param name="api_key">The Shodan API key for your account.</param>
        public WebAPI(string apiKey)
        {
            API_KEY = apiKey;
        }

        /// <summary>
        /// Get all the information Shodan has on the IP.
        /// </summary>
        /// <param name="ip">IP of the computer to look up</param>
        /// <returns>A Host object with the banners and location information.</returns>
        public Host GetHost(IPAddress ip)
        {
            string str_ip = ip.ToString();

            // Send the request
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["ip"] = str_ip;
            Dictionary<string, object> res_dict = SendRequest("host", args);

            Host host = new Host(res_dict);
            return host;
        }

        /// <summary>
        /// Get all the information Shodan has on the IP (given as a string).
        /// </summary>
        /// <param name="ip">IP of the computer to look up</param>
        /// <returns>A Host object with the banners and location information.</returns>
        public Host GetHost(string ip)
        {
            return GetHost(IPAddress.Parse(ip));
        }

        /// <summary>
        /// Search the Shodan search engine for computers matching the given search criteria.
        /// </summary>
        /// <param name="query">The search query for Shodan; identical syntax to the website.</param>
        /// <param name="offset">The starting position for the search cursor. Only for enterprise customers.</param>
        /// <param name="limit">The number of hosts to return (max. 100) per search query. Only for enterprise customers.</param>
        /// <returns>A SearchResult object that contains a List of Hosts matching the query and the total number of results found.</returns>
        public SearchResult Search(string query, int offset=0, int limit=50)
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["q"] = query;
            args["o"] = offset.ToString();
            args["l"] = limit.ToString();
            Dictionary<string, object> res_dict = SendRequest("search", args);

            SearchResult result = new SearchResult(res_dict);
            return result;
        }

        /// <summary>
        /// Internal wrapper function to send API requests.
        /// </summary>
        /// <param name="api_func">The API function to call.</param>
        /// <param name="args">The arguments to pass to the given API function.</param>
        /// <returns>A Dictionary<string, object> with the deserialized JSON information.</returns>
        private Dictionary<string, object> SendRequest(string api_func, Dictionary<string, string> args)
        {
            // Convert the arguments to a query string
            string str_args = ToQuerystring(args);

            // Send the request
            Stream response = web_client.OpenRead(BASE_URL + api_func + str_args + "&key=" + API_KEY);

            // Read the response into a string
            StreamReader reader = new StreamReader(response);
            string data = reader.ReadToEnd();
            reader.Close();

            // Turn the JSON string into a native dictionary object
            Dictionary<string, object> result = json_parser.Deserialize<Dictionary<string, object>>(data);

            // Raise an exception if an error was returned
            if (result.ContainsKey("error"))
            {
                throw new System.ArgumentException((string)result["error"]);
            }

            return result;
        }

        private string ToQuerystring(Dictionary<string, string> dict)
        {
            return "?" + string.Join("&", dict.Select(x => string.Format("{0}={1}", HttpUtility.UrlEncode(x.Key), HttpUtility.UrlEncode(x.Value))));
        }
    }

    public class SearchResult
    {
        private int numResults; // total # of results
        private List<Host> hosts;

        public int NumResults { get { return numResults; } }
        public List<Host> Hosts { get { return hosts; } }

        public SearchResult(Dictionary<string, object> results)
        {
            // Get the total number of results
            numResults = (int)results["total"];

            // Loop through the matches and create host entries
            hosts = new List<Host>();
            foreach (Dictionary<string, object> item in (ArrayList)results["matches"])
            {
                hosts.Add(new Host(item, true));
            }
        }
    }

    public class ServiceBanner
    {
        private int port;
        private string banner;
        private DateTime timestamp;

        public int Port { get { return port; } }
        public string Banner { get { return banner; } }
        public DateTime Timestamp { get { return timestamp; } }

        public ServiceBanner(int arg_port, string arg_banner, DateTime arg_timestamp)
        {
            port = arg_port;
            banner = arg_banner;
            timestamp = arg_timestamp;
        }
    }

    public class HostLocation
    {
        private string country_code;
        private string country_name;
        private string city;
        private double latitude;
        private double longitude;

        public string CountryCode { get { return country_code; } }
        public string CountryName { get { return country_name; } }
        public string City { get { return city; } }
        public double Latitude { get { return latitude; } }
        public double Longitude { get { return longitude; } }

        public HostLocation(Dictionary<string, object> host)
        {
            // Extract the info out of the host dictionary and put it in the local properties
            if (host.ContainsKey("country_name"))
                country_name = (string)host["country_name"];

            if (host.ContainsKey("country_code"))
                country_code = (string)host["country_code"];

            if (host.ContainsKey("city"))
                city = (string)host["city"];

            if (host.ContainsKey("latitude"))
            {
                latitude = (double)((decimal)host["latitude"]);
                longitude = (double)((decimal)host["longitude"]);
            }
        }

        /// <summary>
        /// Check whether there are valid coordinates available for this location.
        /// </summary>
        /// <returns>true if there are latitude/ longitude coordinates, false otherwise.</returns>
        public Boolean HasCoordinates()
        {
            if (Latitude != 0 && Longitude != 0)
            {
                return true;
            }
            return false;
        }
    }

    public class Host
    {
        /*
         * Setup the properties
         */
        private List<ServiceBanner> banners;
        private IPAddress ip = IPAddress.None;
        private List<string> hostnames;
        private HostLocation location = null;
        private Boolean simple = false;

        public List<ServiceBanner> Banners { get { return banners; } }
        public IPAddress IP { get { return ip; } }
        public List<string> Hostnames { get { return hostnames; } }
        public HostLocation Location { get { return location; } }

        // Used to differentiate between hosts from Search() results and direct GetHost() queries
        public Boolean IsSimple { get { return simple; } }

        public Host(Dictionary<string, object> host, Boolean simple=false)
        {
            CultureInfo provider = CultureInfo.InvariantCulture;

            // Extract the info out of the host dictionary and put it in the local properties
            ip = IPAddress.Parse(host["ip"].ToString());

            // Hostnames
            ArrayList tmp = (ArrayList)host["hostnames"];
            hostnames = tmp.Cast<string>().ToList();

            // Banners
            banners = new List<ServiceBanner>();

            if (host["data"] is ArrayList)
            {
                tmp = (ArrayList)host["data"];
                foreach (Dictionary<string, object> data in tmp)
                {
                    DateTime timestamp = DateTime.ParseExact((string)data["timestamp"], "dd.MM.yyyy", provider);
                    banners.Add(new ServiceBanner((int)data["port"], (string)data["banner"], (DateTime)timestamp));
                }
            }
            else if (host["data"] is string)
            {
                DateTime timestamp = DateTime.ParseExact((string)host["updated"], "dd.MM.yyyy", provider);
                banners.Add(new ServiceBanner((int)host["port"], (string)host["data"], (DateTime)timestamp));
            }

            // Location
            location = new HostLocation(host);
        }
    }
}
