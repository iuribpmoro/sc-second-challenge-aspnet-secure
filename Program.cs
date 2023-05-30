using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;

// Libs to fix XSS
using System.Text.RegularExpressions; // to use Regex.IsMatch
using System.Web; // to use HttpUtility.HtmlEncode

// Import Guid
using System;

// Import Path
using System.IO;

public class User
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}

public class Product
{
    public int? Id { get; set; }
    public string? Name { get; set; }
    public decimal? Price { get; set; }
    public string? Image { get; set; }
}

public static class AuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder app)
    {
        return app.Use(async (context, next) =>
        {
            var userIdString = context.Session.GetString("UserId");

            if (string.IsNullOrEmpty(userIdString))
            {
                context.Response.Redirect("/");
                return;
            }

            await next();
        });
    }
}

public class Startup
{
    private static readonly List<User> users = new List<User>
    {
        new User { Id = Guid.NewGuid(), Name = "Alice", Email = "alice@example.com", Password = "password1" },
        new User { Id = Guid.NewGuid(), Name = "Bob", Email = "bob@example.com", Password = "password2" },
        new User { Id = Guid.NewGuid(), Name = "Charlie", Email = "charlie@example.com", Password = "password3" }
    };

    private static readonly List<Product> products = new List<Product>
    {
        new Product { Id = 1, Name = "Shoes", Price = 50, Image = "shoes.jpg" },
        new Product { Id = 2, Name = "Apple", Price = 5, Image = "apple.png" },
        new Product { Id = 3, Name = "Hat", Price = 15, Image = "hat.jpg" }
    };

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        // Add session with cookie samesite none
        services.AddSession(options =>
        {
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });
        services.AddDistributedMemoryCache();
    }

    private static bool IsWhitelisted(string path)
    {
        var whitelist = new[] { "/", "/login", "/public" };
        return whitelist.Contains(path);
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseRouting();

        app.UseSession();

        // Authentication middleware called only when the path is not whitelisted
        app.UseWhen(context => !IsWhitelisted(context.Request.Path), appBuilder =>
        {
            appBuilder.UseAuthenticationMiddleware();
        });

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/", async context =>
            {
                await context.Response.WriteAsync(@"
                    <h1>Welcome to the Shop</h1>
                    <form action=""/login"" method=""post"">
                        <label for=""email"">Email:</label>
                        <input type=""email"" name=""email"" id=""email"" required>
                        <label for=""password"">Password:</label>
                        <input type=""password"" name=""password"" id=""password"" required>
                        <button type=""submit"">Login</button>
                    </form>
                ");
            });

            endpoints.MapPost("/login", context =>
            {
                var email = context.Request.Form["email"];
                var password = context.Request.Form["password"];
                var user = users.Find(u => u.Email == email && u.Password == password);

                if (user != null)
                {
                    context.Session.SetString("UserId", user.Id.ToString());
                    context.Response.Redirect("/products");
                    return System.Threading.Tasks.Task.CompletedTask;
                }
                else
                {
                    return context.Response.WriteAsync("Invalid credentials. Please try again.");
                }
            });

            endpoints.MapGet("/products", context =>
            {
                var userIdString = context.Session.GetString("UserId");

                if (string.IsNullOrEmpty(userIdString))
                {
                    context.Response.Redirect("/");
                    return System.Threading.Tasks.Task.CompletedTask;
                }

                var userId = Guid.Parse(userIdString);
                var user = users.Find(u => u.Id == userId);

                if (user != null)
                {
                    var productsHtml = string.Join("", products.Select(p => $@"
                        <li>
                            <img src=""/images?name={p.Image}"" alt=""{p.Name}"" width=""100"">
                            <h3>{p.Name}</h3>
                            <p>Price: ${p.Price}</p>
                            <form action=""/place-order"" method=""post"">
                                <input type=""hidden"" name=""product_id"" value=""{p.Id}"">
                                <button type=""submit"">Place Order</button>
                            </form>
                        </li>
                    "));

                    return context.Response.WriteAsync($@"
                        <h1>Product Listing</h1>
                        <ul>
                            {productsHtml}
                        </ul>
                    ");
                }

                context.Response.Redirect("/");
                return System.Threading.Tasks.Task.CompletedTask;
            });

            endpoints.MapGet("/images", context =>
            {
                var imageName = context.Request.Query["name"].ToString();

                // Filtro para evitar Path Traversal
                string pattern = @"^[a-zA-Z0-9.\s]*$";
                if (!Regex.IsMatch(imageName, pattern))
                {
                    return context.Response.WriteAsync("Invalid image name!");
                }

                // Define base path
                string basePath = Directory.GetCurrentDirectory() + "/public/images";
                var filePath = Path.Combine(basePath, imageName);

                // Cannonicalize path
                filePath = Path.GetFullPath(filePath);

                // Check if filename is inside the base path
                if (!filePath.StartsWith(basePath))
                {
                    return context.Response.WriteAsync("Invalid image name!");
                }
                else if (!File.Exists(filePath))
                {
                    return context.Response.WriteAsync("Image not found!");
                }

                return context.Response.SendFileAsync(filePath);
            });

            endpoints.MapPost("/place-order", context =>
            {
                var userIdString = context.Session.GetString("UserId");

                if (string.IsNullOrEmpty(userIdString))
                {
                    context.Response.Redirect("/");
                    return System.Threading.Tasks.Task.CompletedTask;
                }

                var userId = Guid.Parse(userIdString);
                var user = users.Find(u => u.Id == userId);
                var productId = int.Parse(context.Request.Form["product_id"]);

                if (user != null)
                {
                    var product = products.Find(p => p.Id == productId);

                    if (product != null)
                    {
                        return context.Response.WriteAsync($@"
                            <h1>Order Placed</h1>
                            <p>Thank you for placing an order for {product.Name}.</p>
                        ");
                    }
                    else
                    {
                        context.Response.StatusCode = 404;
                        return context.Response.WriteAsync("Product not found");
                    }
                }

                context.Response.Redirect("/");
                return System.Threading.Tasks.Task.CompletedTask;
            });
        });
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
}
