using System;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Cosmos.Fluent;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualBasic;
using System.Linq;
using System.Configuration;

[assembly: FunctionsStartup(typeof(MyNamespace.Startup))]

namespace MyNamespace
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.Services.AddHttpClient();
            //var config = (IConfiguration)builder.Services.First(d => d.ServiceType == typeof(IConfiguration)).ImplementationInstance;

           // var connectionString2 = Environment.GetEnvironmentVariable("CosmosDBConnectionString");
            //var connectionString = ConfigurationManager.AppSettings["CosmosDBConnectionString"];
            builder.Services.AddSingleton((s) =>
            {
               // CosmosClientBuilder cosmosClientBuilder = new CosmosClientBuilder(ConfigurationManager.AppSettings["CosmosDBConnectionString"]);
                CosmosClientBuilder cosmosClientBuilder = new CosmosClientBuilder(Environment.GetEnvironmentVariable("CosmosDBConnectionString"));

                return cosmosClientBuilder.WithConnectionModeGateway()
                    .Build();
            });

        }
    }
}