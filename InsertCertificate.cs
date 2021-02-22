using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.Collections;
using System.Text.Json;
using System.Collections.Generic;
using System.Configuration;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Configuration;
using Microsoft.Azure.Cosmos.Fluent;
using Newtonsoft.Json.Converters;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;

namespace CertificateCheckerFunctionApp
{

    public class InsertCertificate
    {
        private readonly IConfiguration _config;
        private CosmosClient _cosmosClient;
        private Database _database;
        private Container _container;
        public InsertCertificate(
            IConfiguration config,
            CosmosClient cosmosClient
        )
        {
            _config = config;
            _cosmosClient = cosmosClient;
            _database = _cosmosClient.GetDatabase(Environment.GetEnvironmentVariable("CosmosDB_DB_Name"));
            _container = _database.GetContainer(Environment.GetEnvironmentVariable("CosmosDBContainer"));
        }
        //public static CosmosClient cosmosClient = new CosmosClientBuilder("CosmosDBConnectionString").Build();

        public static HttpClient httpClient = new HttpClient();

        [FunctionName("InsertCertificate")]
        public  async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req, [CosmosDB(
                databaseName: "dnsresults",
                collectionName: "dnsresults",
                ConnectionStringSetting = "CosmosDBConnectionString")] IAsyncCollector<CertInformation> document,
            ILogger log)
        {
            //Declare Variables
            //IList<CertInformation> certList = new List<CertInformation>();
            //IList<string> url = new List<string>();
            ConcurrentBag<CertInformation> certList = new ConcurrentBag<CertInformation>();
            ConcurrentBag<string> url = new ConcurrentBag<string>();


            log.LogInformation("C# HTTP trigger function processed a request.");
            var requestBodyJson = await new StreamReader(req.Body).ReadToEndAsync();
            Stopwatch timer = new Stopwatch();
            //timer.Start();

            try
            {
                //Check if body contains URLS to check
                if (requestBodyJson != "")
                {
                    List<TempJsonBody> tempBody = System.Text.Json.JsonSerializer.Deserialize<List<TempJsonBody>>(requestBodyJson);
                    log.LogInformation($"Count: {tempBody.Count}");
                    foreach (TempJsonBody temp in tempBody)
                    {
                        url.Add(temp.Name);
                    }
                }
                //Else Check the query string for URLs to check
                else if (req.Query["url"].ToString() != null)
                {
                    url.Add( req.Query["url"]);
                }
                else return new BadRequestObjectResult("No value passed in header or body.");
            }
            catch (Exception e)
            {
                log.LogError($"Exception occurred: {e}");
                return new BadRequestObjectResult($"Failed to get parsed cert from header or body with exception{e}");
            }
            //timer.Stop();
            //log.LogInformation($"Pulling body {timer.ElapsedMilliseconds} ms");

            //timer.Reset();
            timer.Start();
            //Logic for checking if URL is the correct format
            //foreach (string hostname in url)
            Parallel.ForEach(url, async(hostname) =>
            { 
                try
                {
                    await Dns.GetHostEntryAsync(hostname);
                }
                catch(Exception e)
                {
                    log.LogError($"DNS resolution for {hostname} failed with {e}");
                    //return new BadRequestObjectResult($"Dns Resolution failed for {hostname}. Please fix or remove this URL and resubmit");
                }
            });
            timer.Stop();
            log.LogInformation($"Validating DNS {timer.ElapsedMilliseconds} ms");

            //Foreach URL try to get Cert information
            timer.Reset();
            timer.Start();
            //foreach (string urlValue in url)
            Parallel.ForEach(url, async(urlValue) =>
             {
                 CertInformation cert = new CertInformation();
                 try
                 {
                    //Creating cert object with properties 
                    ///Very questionable code that will probably cause blocking/deadlocking at some point......Trying to optimize calls to be parallel to spped up execution time. If any deadlocking issues revert back to foreach
                    cert =  GetCertInformation(urlValue, cert, log).Result;
                    cert.Region = Environment.GetEnvironmentVariable("region");
                    certList.Add(cert);
                 }
                 catch (Exception e)
                 {
                     log.LogError($"Exception Occurred trying to pull certificate for {urlValue} : {e}");
                     //return new BadRequestObjectResult($"Failed to get parse cert with exception {e}");
                 }
             });

            timer.Stop();
            log.LogInformation($"Total time for all certs info {timer.ElapsedMilliseconds} ms");

            //Convert to JSON
            string jsonString = System.Text.Json.JsonSerializer.Serialize(certList);

            timer.Reset();
            timer.Start();
            //foreach (var certItem in certList)
            Parallel.ForEach(certList, async (certItem) =>
            {
                try
                {
                    await document.AddAsync(certItem);
                }
                catch (Exception e)
                {
                    log.LogError($"Failed to update DB for {certItem.URL} with exception: {e}");
                }
            });
            timer.Stop();
            log.LogInformation($"Final Step {timer.ElapsedMilliseconds} ms");
            return new OkObjectResult(jsonString);
        }
        //Creating Certificate properties to send to cosmos
        public static async Task<CertInformation> GetCertInformation(string urlValue, CertInformation cert, ILogger log)
        {
            Stopwatch timer = new Stopwatch();
            timer.Start();
            X509Certificate2 certObject = await GetServerCertificateAsync("https://" + urlValue);
            timer.Stop();
            log.LogInformation($"Getting Cert {urlValue} {timer.ElapsedMilliseconds} ms");

            //timer.Reset();
            //timer.Start();
            cert.id = urlValue;
            cert.URL = certObject.Subject;
            cert.CertExpiration = certObject.GetExpirationDateString();
            cert.ThumbPrint = certObject.Thumbprint;
            cert.ValidFromDate = certObject.GetEffectiveDateString();
            cert.RawCert = Convert.ToBase64String(certObject.RawData);
            cert.LastUpdateTime = DateTime.Now.ToUniversalTime();
            var TimeTilExpiration = IsCertificateExpiring(cert, log);
            cert.TimeTilExpiration = TimeTilExpiration.Days.ToString();

            //Pull the SAN from certificate https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509nametype?view=net-5.0
            foreach (X509Extension extension in certObject.Extensions)
            {
                if (extension.Oid.FriendlyName.Equals("Subject Alternative Name"))
                {
                    // Create an AsnEncodedData object using the extensions information.
                    AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                    cert.SAN = asndata.Format(true);
                }
            }

            if (TimeTilExpiration.TotalSeconds > 0)
            {
                cert.IsExpired = false;
                log.LogInformation($"Cert for {cert.URL} expires in {TimeTilExpiration.TotalDays} days.");
            }
            else
            {
                cert.IsExpired = true;
                log.LogInformation($"Cert for {cert.URL} EXPIRED {TimeTilExpiration.TotalDays} days ago.");
            }
            //timer.Stop();
            //log.LogInformation($"Creating certObject for {urlValue} {timer.ElapsedMilliseconds} ms");

            return cert;
        }

        //Checking cert expiration
        static TimeSpan IsCertificateExpiring(CertInformation cert, ILogger log)
        {
            TimeSpan expirationTime = DateTime.Parse(cert.CertExpiration) - DateTime.Now;
            return expirationTime;
        }
        //Pulling Cert from HTTPS Request from url
        static async Task<X509Certificate2> GetServerCertificateAsync(string url)
        {

            X509Certificate2 certificate = null;
            var httpClientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, __, ___) =>
                {
                    certificate = new X509Certificate2(cert.GetRawCertData());
                    return true;
                }
            };
                httpClient = new HttpClient(httpClientHandler);
                await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));

            return certificate ?? throw new NullReferenceException();
        }
    }
}
