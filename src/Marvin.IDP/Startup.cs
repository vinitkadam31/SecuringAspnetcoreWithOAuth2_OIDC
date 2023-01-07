// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Logging;
using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Marvin.IDP
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }

        public Startup(IWebHostEnvironment environment)
        {
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var marvinIDPDataDBConnectionString = "Server=(localdb)\\mssqllocaldb;Database=MarvinIDPDataDB;Trusted_Connection=True;";

            // uncomment, if you want to add an MVC-based UI
            services.AddControllersWithViews();

            var builder = services.AddIdentityServer()
                //.AddInMemoryIdentityResources(Config.Ids)
                //.AddInMemoryApiResources(Config.Apis)
                //.AddInMemoryClients(Config.Clients)
                .AddTestUsers(TestUsers.Users);

            //builder.AddDeveloperSigningCredential();

            builder.AddSigningCredential(LoadCertificateFromStore());
            //IdentityModelEventSource.ShowPII = true;

            var migrationAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            builder.AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = builder => builder.UseSqlServer(marvinIDPDataDBConnectionString,
                    options => options.MigrationsAssembly(migrationAssembly));
            });

            builder.AddOperationalStore(options =>
            {
                options.ConfigureDbContext = builder => builder.UseSqlServer(marvinIDPDataDBConnectionString,
                    options => options.MigrationsAssembly(migrationAssembly));
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            InitializeDatabase(app);

            // uncomment if you want to add MVC
            app.UseStaticFiles();
            app.UseRouting();

            app.UseIdentityServer();

            // uncomment, if you want to add MVC
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }

        public X509Certificate2 LoadCertificateFromStore()
        {
            string thumbprint = "3DF890786E7FD6B771C9A1D376A2E72EE56B0162";
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
                if(certCollection.Count == 0)
                {
                    throw new Exception("The specified certificate wasnt found");
                }

                return certCollection[0];
            }
        }

        private void InitializeDatabase(IApplicationBuilder app)
        {
            using(var servicescope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                servicescope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = servicescope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();

                if(!context.Clients.Any())
                {
                    foreach (var client in Config.Clients)
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in Config.Ids)
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.Apis)
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
            }
        }
    }
}
