
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using StackExchange.Redis;
using System;
using System.Runtime.Intrinsics.X86;
using System.Security.Claims;
using System.Text;
using User.Mgmt.Data.DataContext;
using User.Mgmt.Data.Models;
using User.Mgmt.Service.CustomMiddleware;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Services;

//################## ASP.NET Core application 2 phases lifecycle #########################
//   PHASE 1: Build/Configuration Phase (Configure the Toolbox) i.e: var builder = WebApplication.CreateBuilder(args);

//is the foundation of the modern application startup template
//Its job is to initialize a WebApplicationBuilder instance pre-configured with industry-standard
//  defaults for web hosting, logging, configuration, and dependency injection
//Instead of forcing you to configure everything from scratch,
//  CreateBuilder(args) executes a series of "under the hood" operations:
//      Web Server Configuration: It configures Kestrel (the high-performance cross-platform web server)
//      as the default server and integrates it with IIS if running on Windows.
//  Multi-Source Configuration: It automatically wires up a ConfigurationManager
//      that reads application settings sequentially from:
//          -appsettings.json
//          -appsettings.{Environment}.json (e.g., appsettings.Development.json)
//          -User Secrets(when running in a local Development environment).
//          -Environment variables
//          -Command-line arguments 
//  Logging: It configures default logging providers so you can output logs directly to the Console,
//      Debug window, or EventSource.
//  Dependency Injection (DI) Container: It initializes an empty built-in DI container (builder.Services)
//      ready for you to register your custom framework dependencies.
//  Environment Detection: It determines whether your app is running in Development, Staging,
//      or Production  based on environment variables.
var builder = WebApplication.CreateBuilder(args);
//The args parameter passes command-line arguments into the builder.
//This allows you to override configurations dynamically when starting the application from a terminal.
//For example, running dotnet run --urls="http://localhost:5001" intercepts the application startup
//  parameters via args, updating the server behavior instantly without code modifications.


//Configuration property on this builder provides a centralized way to access your application's settings
// i.e. appsettings.json,
// appsettings.{Environment}.json (Environment-specific files, like Development or Production)
// User Secrets (For local development sensitive data)
// Environment Variables (Common for Docker/Cloud deployments)
// Command-line arguments
var _configuration = builder.Configuration;

var jwtSettingsSection = _configuration.GetSection("JWTSettingsSection")
                                       .Get<JwtSettings>()
                                       ?? throw new InvalidOperationException("JWTSettingsSection is missing.");

builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("JWTSettingsSection"));

//********** builder.Services: Accesses the service collections in Program.cs ********************

// Registers your custom DbContext subclass (AppDbContext) with the dependency injection system.
//Not Thread-Safe: A DbContext is not thread-safe.
//Never register it as a Singleton,
//or you will run into concurrency errors,
//data corruption,
//and tracker mix-ups.
//MOST of the time; registers your DbContext as a scoped service
//it means ASP.NET Core automatically creates one instance of AppDbContext per HTTP request
//and disposes of it when the request finishes
builder.Services.AddDbContext<AppDbDataContext>(options =>
{
    //A lambda expression used to configure the database provider (such as SQL Server or PostgreSQL)
    //and its connection string.
    options.UseSqlServer(builder.Configuration.GetConnectionString("DbConnStrng"));
});

builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
    ConnectionMultiplexer.Connect("localhost:6379, connectTimeout=10000, syncTimeout=10000, abortConnect = false"));

builder.Services.AddScoped<ITokenBlacklistService, TokenBlacklistService>();


// builder.Services.AddIdentity() is an ASP.NET Core dependency injection method
// that registers the full user management and role management identity system
// using custom user and role classes
//AddIdentity<TUser, TRole>:
//Registers the full identity framework, UserManager, SignInManager, and RoleManager,
//giving you complete manual control over UI endpoints and role support.
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>  //<ApplicationUser, IdentityRole> means multiple generic type parameters 
{
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredUniqueChars = 0;  //0 means false; default: 1
        options.Password.RequiredLength = 8;

        options.User.RequireUniqueEmail = true;

        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 3;
        options.Lockout.AllowedForNewUsers = true;

        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._+!@#$%^&*";

    })
    //Tells Identity to use your Entity Framework Core database context (AppDbDataContext)
    //  to save user and role data to the database.
    .AddEntityFrameworkStores<AppDbDataContext>()

    //Default Registration: Calling .AddSignInManager() without generic arguments
    //registers the standard IdentityBuilderExtensions.AddSignInManager Method.
    /*
     * WHAT IT IS?
     * registers the SignInManager<TUser> service into the dependency injection container, 
     *  which handles user sign-in operations like logging in, logging out, 
     *  and managing external authentication.
     */
    //You only need to explicitly call .AddSignInManager() when configuring a CUSTOM identity core setup
    /*
     * PURPOSE?
     * Enables User Authentication Operations: It registers SignInManager<TUser>, 
     *  which provides built-in methods for handling user logins, logouts, and security checks     
     */
    .AddSignInManager()

    /*
     * Why You Need It?
     * You use .AddRoles() in ASP.NET Core to register role-based authorization services 
     * Role-Based Access Control (RBAC): By default, ASP.NET Core Identity includes 
     *  user management (logins, passwords, and profiles), it does not enable role services automatically. 
     *  Calling .AddRoles() turns on role support     
     */
    .AddRoles<IdentityRole>()

    //Adds default providers used to generate tokens for
    //  registration, forgot password resets, email confirmations, and two-factor authentication
    .AddDefaultTokenProviders();

//sets JSON Web Token (JWT) Bearer as the primary and default way to handle
//  user authentication and authorization in an ASP.NET Core application. 
builder.Services.AddAuthentication(options =>
{
    //Tells the app to automatically look for, read,
    //and validate a JWT token on incoming requests to figure out who the user is
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;

    //Tells the app how to reply (by issuing a Bearer challenge) when a user is not logged in
    //  or sends an invalid token, resulting in a 401 Unauthorized response
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

    //Acts as a catch-all setting.
    //It sets a fallback value for any other authentication task
    //  that does not have a specific scheme assigned
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    /*Why use options.DefaultScheme?: 
     * Setting these defaults means you do not have to manually specify: 
     *      [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] 
     *  on every single controller or action
    */

}).AddCookie(options =>
{
    //Configures AddCookie options for HttpOnly cookie 
    options.Cookie.Name = "HttpOnlyCookieToken";
})
.AddJwtBearer(options => //setting up Jwt Token Bearer authentication configuration options
{
    //Saves the JWT token in the authentication context.
    //This allows you to retrieve the token later in your controllers
    //or services using HttpContext.GetTokenAsync("access_token").
    options.SaveToken = true;

    //Disables the requirement for HTTPS when downloading metadata.
    //WARNING: While this is fine for local development,
    //  it should be changed to TRUE in production to ensure secure transit.
    options.RequireHttpsMetadata = false;

    // configures rules used to check & verify JSON Web Tokens (JWT) in .NET authentication middleware.
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        //ensures that the server will verify that the token was issued
        //  by a trusted authority (matching your ValidIssuer).
        ValidateIssuer = true,

        //Ensures that the server will verify that the token was intended
        //  for your specific application (matching your ValidAudience).
        ValidateAudience = true,

        ValidateLifetime = true, // Enforces token expiration checks

        ValidateIssuerSigningKey = true,

        ClockSkew = TimeSpan.Zero, // Removes the default 5-minute grace period for expiration

        //pull the expected audience and issuer values from your
        //  appsettings.json configuration file to check against incoming tokens.
        ValidAudience = jwtSettingsSection.ValidAudience, // _configuration["JWTSettingsSection:ValidAudience"],

        ValidIssuer = jwtSettingsSection.ValidIssuer, // _configuration["JWTSettingsSection:ValidIssuer"],

        //Specifies the cryptographic key used to sign the token.
        //It converts your secret string from appsettings.json into a SymmetricSecurityKey.
        //The system uses this to verify that the token hasn't been tampered with.     
        IssuerSigningKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettingsSection.Secret!))  //_configuration["JWTSettingsSection:Secret"]
    };

    options.Events = new JwtBearerEvents
    {
        //2 options: use OnMessageReceived is more efficient
        //This event is triggered whenever a JWT token is received in an incoming request.
        // or use OnTokenValidated event to check for blacklisted tokens as a custom middleware class 
        OnMessageReceived = async context =>
        {
            //context.Token = context.Request.Cookies["HttpOnlyCookieToken"];
            var authHeader = context.Request.Headers["Authorization"].ToString();

            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return;
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            var tokenBlacklistService = context.HttpContext.RequestServices.GetRequiredService<ITokenBlacklistService>();

            // Extract the JTI claim from the validated token
            //var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

            var isBlacklisted = await tokenBlacklistService.IsTokenBlacklistedAsync(token ?? string.Empty);

            if (isBlacklisted is true)
            {
                // Reject the token immediately if it exists in Redis
                context.Fail("This token has been revoked.");
            }

            await Task.CompletedTask;
        },

        OnChallenge = async context =>
        {
            // Skip the default logic so we can write our own response
            context.HandleResponse();

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";

            // Retrieve the error message passed into context.Fail()
            string errorMessage = context.AuthenticateFailure?.Message ?? "Unauthorized.";

            var responseBody = new { error = errorMessage };
            await context.Response.WriteAsJsonAsync(responseBody);
        }
    };
});

//This line of code fetches configuration data from your application's settings
//  (typically appsettings.json) and maps it directly to a strongly typed C# object.
EmailConfiguration emailConfig = builder.Configuration
    .GetSection("EmailConfigSection")  //Targets a specific configuration section named "EmailConfiguration".
    .Get<EmailConfiguration>() //Binds that JSON section directly to a C# class instance 'emailConfig' of the type EmailConfiguration matching its property names.
    ?? throw new InvalidOperationException("EmailConfigSection is missing.");

//registers a specific instance of an object (emailConfig)
//  as a Singleton service in the built-in Dependency Injection (DI) container.
//DI container will create or hold only one single instance of this configuration object
//  for the entire lifetime of your application.
//Pre-constructed: Because you are passing 'emailConfig' directly into the method,
//  you are telling the container to use an instance you have already created,
//  rather than letting the container instantiate it.
builder.Services.AddSingleton(emailConfig);

//it tells the dependency injection (DI) system that whenever a class asks for IEmailService,
//  it should create and provide an instance of EmailService.
// DI container creates a new EmailService instance once per client request
//  (such as a single HTTP web request).
//That same instance is shared across all classes handling that specific request
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddScoped<IUserMgmtService, UserMgmtService>();

//forces users to verify their email address before they are allowed to sign into the application,
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
});

//any generated token will expire exactly 10 hours after it is issued.
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(10);
});

//registers the backend services required to use Web API controllers in an ASP.NET Core application
//Instead of forcing developers to register dozens of internal MVC architecture framework pieces one by one,
//AddControllers() acts as a wrapper that automatically bundles and executes several extension methods:
builder.Services.AddControllers();  //// 1. REGISTER THE SERVICES

// is a service registration method in ASP.NET Core that discovers
//  and exposes metadata & finds all the routes you mapped (like app.MapGet or app.MapPost),
//  and compiles a detailed map of what inputs they expect and what outputs they return
//Why is it needed?
//  Historically, ASP.NET Core used Controllers. When you call builder.Services.AddControllers();,
//      it automatically runs a background process (AddApiExplorer) that reflects over your
//      controller classes to figure out your API structure
//  Minimal APIs (introduced in .NET 6) do not use controllers;
//      they map routes directly in Program.cs.
//      Because they lack the class-and-method structure of controllers,
//      Swagger cannot "see" them by default. so Figures out WHAT endpoints exist (Minimal API metadata)
builder.Services.AddEndpointsApiExplorer();
/*
 (Note: Starting in newer versions like .NET 9, Microsoft introduced a new built-in package 
    Microsoft.AspNetCore.OpenAPI via builder.Services.AddOpenApi(), 
    which natively handles endpoint discovery without strictly requiring 
    the older AddEndpointsApiExplorer step for documentation rendering)
 */


//builder.Services.AddSwaggerGen(); //comment this line

//1. primary job is inspect your API's controllers, routes, models,
//and actions to automatically build the OpenAPI (Swagger) JSON document that describes your entire API
//If your endpoints are protected, you can use AddSwaggerGen to add a lock icon
//      and authorization interface to your Swagger UI page:
builder.Services.AddSwaggerGen(options => //(The Brain): Finds all your endpoints and builds the underlying API metadata.
{
        //1. this defines the API document metadata
        options.SwaggerDoc(
            "v1", 
            new OpenApiInfo 
            { 
                Title = "Authentication API", 
                Version = "v1",
                Description = "An ASP.NET Core Web API for managing inventory.",
                Contact = new OpenApiContact
                {
                    Name = "Dev Support",
                    Email = "support@example.com"
                }
            }
        );

    //2. defines how your API handles authentication and authorization.
    //  Adds an "Authorize" Button: It tells Swagger UI to display an Authorize button at the top
    //      of the documentation page.
    //  Defines the Auth Scheme: It registers a security scheme
    //      (such as JWT Bearer tokens, API Keys, or OAuth2) as a template that Swagger can reference.
    //  Configures Request Headers: It specifies where the token or key goes
    //      (e.g., inside the HTTP Authorization header) and how the user should format it.
    options.AddSecurityDefinition(
            "Bearer", 
     new OpenApiSecurityScheme
                {

                    //is an OpenAPI configuration setting used to specify that an API parameter
                    //  (such as an API key, authorization token, or custom header)
                    //  must be passed via the HTTP request header rather than the URL query or path
                    In = ParameterLocation.Header,

                    //tells the Swagger configuration in ASP.NET Core that your API
                    //  uses an HTTP header authentication scheme, such as Bearer tokens or Basic authentication
                    Type = SecuritySchemeType.Http,

                    //tells the API client to send access tokens in the HTTP request header
                    //  as Authorization: Bearer <token>
                    //It grants access to whoever "bears" or holds the token,
                    //  meaning no extra cryptographic proof is required on each request.
                    Scheme = "Bearer",

                    Description = "Enter your JWT token like this: Bearer {your_token}",

                    Name = "Authorization",

                    //a configuration property used in API specifications like OpenAPI (Swagger)
                    //  to indicate that the expected Bearer Authentication token is a JSON Web Token. 
                    BearerFormat = "JWT"
                }
        );

    // 3. Apply the security requirement globally to all CONTROLLERS' endpoints
    //tells Swagger UI that your API endpoints require authentication (such as JWT Bearer tokens or API keys)
    //  Enables the "Authorize" Button: It adds the lock/Authorize button to the top-right corner of the Swagger UI interface.
    //  Sends Credentials with Requests: When a user enters a token or API key in Swagger UI,
    //      this requirement tells Swagger to automatically attach that credential
    //      (e.g., in the Authorization: Bearer <token> header) when testing API endpoints.
    //  Applies Global Rules: By default, it applies the security scheme globally across your API documentation
    options.AddSecurityRequirement(
         new OpenApiSecurityRequirement
                        {   //anonymous object
                            {  
                                new OpenApiSecurityScheme //object instance
                                {
                                    Reference = new OpenApiReference   //object instance
                                    {
                                        //What it is:
                                        // is an enumeration value used to indicate that a $ref (reference)
                                        // object is pointing to a Security Scheme definition.

                                        //What it is used for:
                                        // When parsing or building OpenAPI documents programmatically
                                        // (such as in .NET using Microsoft.OpenApi.Models),
                                        // you use this type to reference security configurations
                                        // (like Bearer tokens, OAuth2, or API keys)
                                        // defined globally in the components/securitySchemes section.
                                        Type = ReferenceType.SecurityScheme,

                                        // Must exactly match the definition ID above in AddSecurityDefinition(...)
                                        Id = "Bearer"  
                                    }
                                },

                                // initialization to specify that a security scheme applies globally
                                //  to the entire API without requiring any specific OAuth2 scopes.

                                // It tells OpenAPI: "Use this security scheme,
                                // but no specific scopes are needed/required
                                // to access this endpoint."
                                new string[] { }  //or use: new List<string>()
                            }
                        }
         );
    }
);

//used during application startup to register an in-memory caching service.
//It configures your application to use a single,
//shared instance of MemoryCache across its entire lifecycle
builder.Services.AddSingleton<MemoryCache>();
//MemoryCache class being registered. It is a built-in .NET class that allows you to store data
//in the server's local memory (RAM) using key-value pairs.

// 1. Add CORS services and define a policy
//It tells the application that you plan to use CORS policies to allow or
//block requests coming from different domains, ports, or protocols. 
builder.Services.AddCors( options => 
{
    options.AddPolicy("CorsAllowAllPolicy", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

//############### Middleware pipeline Configurations #################################
// ASP.NET Core app lifecycle PHASE 2: Execution/Runtime Phase (Lock the Toolbox & Run)
var app = builder.Build();

app.UseRouting();

// 2. Enable the CORS middleware in the request pipeline
// Note: Must be placed before UseAuthorization() and typically after UseRouting()
app.UseCors("CorsAllowAllPolicy");

// Configure the HTTP request pipeline so ALLOW ONLY Swagger to be viewed if isDevelopment
if (app.Environment.IsDevelopment())
{
    // (The Exposer): Exposes the generated metadata as a JSON endpoint
    //   (usually at /swagger/v1/swagger.json).
    app.UseSwagger();

    //(The Face): Turns that JSON into the interactive, web-based UI where you can view
    //  and test your endpoints.
    app.UseSwaggerUI();
}

// is a built-in middleware method that automatically redirects
// all incoming HTTP requests to their secure HTTPS counterparts.
//The Interception:
//  When a client sends an HTTP request, this middleware intercepts it before it reaches your controllers
//  or pages.
//The Location Header:
//  It calculates the correct HTTPS port and returns a response containing a Location header
//  with the new https:// URL.
//The Client Response:
//  The browser reads the redirect response and automatically makes a fresh,
//  secure request to the HTTPS link
app.UseHttpsRedirection();


//WHO are you?
//When a user sends a request to your application, this middleware intercepts the request,
//looks for credentials (like a JWT token, cookie, or API key),
//validates them, and establishes the user's identity
app.UseAuthentication();

//already using the OnMessageReceived event in AddJwtBearer
//to check for blacklisted tokens, so this middleware is not needed
//app.UseMiddleware<MiddlewareInterceptBlacklistToken>();  //custom middleware to intercept blacklisted tokens

//What are you allowed to do?
//When a user requests a protected endpoint (like an admin panel),
//app.UseAuthorization() intercepts the request.
//It evaluates/enforces the identity context of that user against
//the specific security rules (roles, claims, or custom policies) assigned to that  
/*
 1. Role-Based Check: Restricts access to users belonging to specific groups (e.g., [Authorize(Roles = "Admin")]).
 2. Claim-Based Check: Restricts access based on specific identity attributes, like an email address or an employee ID.
 3. Policy-Based Check: Evaluates custom complex requirements (e.g., "User must be over 21 AND have a valid subscription").
 */
app.UseAuthorization();

/*
 • Enables Attribute Routing: It scans all controller classes registered in your application for routing attributes like [Route], [HttpGet], and [HttpPost].
 • Builds the Route Table: It connects incoming HTTP request URLs to the appropriate controller action methods.
 • Simplifies Program.cs: It combines and replaces the older, more verbose UseRouting() and UseEndpoints() pattern used in previous ASP.NET Core versions.
 */
app.MapControllers(); // 2. ACTIVATE THE ROUTES & Map controller endpoints to the pipeline

// It kicks off the application, binds the server to its designated ports,
// and starts continuously listening for incoming HTTP requests.
//this is like turning on the open sign at a restaurant &  is ready to take orders
app.Run();






//options.Events = new JwtBearerEvents
//{
//    OnTokenValidated = async context =>
//    {
//        //var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

//        var userName = context.Principal?.FindFirst(ClaimTypes.Name)?.Value;

//        if (userName == null)
//        {
//            return;
//        }

//        var securityStampClaim = context.Principal?.FindFirst("SecurityStamp")?.Value;

//        //var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<IdentityUser>>();

//        //var user = await userManager.FindByNameAsync(userName);

//        var user = await context.HttpContext.RequestServices
//            .GetRequiredService<UserManager<ApplicationUser>>()
//            .FindByNameAsync(userName);

//        var currentSecurityStamp = user.SecurityStamp ?? string.Empty;

//        if (securityStampClaim != currentSecurityStamp)
//        {
//            context.Fail("Token has been revoked.");
//        }
//    }
//};