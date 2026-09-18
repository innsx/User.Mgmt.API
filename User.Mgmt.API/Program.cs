//using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using User.Mgmt.Data.DataContext;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Services;
using UserMgmt.Data.Models;

var builder = WebApplication.CreateBuilder(args);

var _configuration = builder.Configuration;

//**********  services registration in the DI container. *******************************

//get DB connection string and register it
builder.Services.AddDbContext<AppDbDataContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DbConnStrng"));
});

// Registers the core Identity services for the specified user and role classes,
//      enabling user management, sign-in, and role features
builder.Services.AddIdentity<ApplicationUserDto, IdentityRole>()

                //Tells Identity to use your Entity Framework Core database context (AppDbDataContext)
                //  to save user and role data to the database.
                .AddEntityFrameworkStores<AppDbDataContext>()

                //Adds default providers used to generate tokens for
                //  password resets, email confirmations, and two-factor authentication
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

    /*Why use it?: 
     * Setting these defaults means you do not have to 
     *  manually specify [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] 
     *  on every single controller or action*/

}).AddJwtBearer(options => //setting up Jwt Token Bearer authentication configuration
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

        ClockSkew = TimeSpan.Zero, // Removes the default 5-minute grace period for expiration

        //pull the expected audience and issuer values from your
        //  appsettings.json configuration file to check against incoming tokens.
        ValidAudience = _configuration["JWT:ValidAudience"],
        ValidIssuer = _configuration["JWT:ValidIssuer"],

        //Specifies the cryptographic key used to sign the token.
        //It converts your secret string from appsettings.json into a SymmetricSecurityKey.
        //The system uses this to verify that the token hasn't been tampered with.
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]))
    };
});

//This line of code fetches configuration data from your application's settings
//  (typically appsettings.json) and maps it directly to a strongly typed C# object.
EmailConfiguration emailConfig = builder.Configuration
    .GetSection("EmailConfiguration")  //Targets a specific configuration section named "EmailConfiguration".
    .Get<EmailConfiguration>();  //Binds that JSON section directly to a C# class instance 'emailConfig' of the type EmailConfiguration matching its property names.

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

//forces users to verify their email address before they are allowed to sign into their application,
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
});

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(10);
});

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

//builder.Services.AddSwaggerGen(); //comment this line
//add more options to SwaggerGen service
builder.Services.AddSwaggerGen(options =>
    {
        //1. this defines the document metadata
        options.SwaggerDoc("v1", new OpenApiInfo { Title = "Authentication API", Version = "v1" });

        //2. Define the Bearer Authentication Scheme
        options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
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

            Description = "Please enter a valid Jwt Token.",
            Name = "Authorization",

            //a configuration property used in API specifications like OpenAPI (Swagger)
            //  to indicate that the expected Bearer Authentication token is a JSON Web Token. 
            BearerFormat = "JWT",

        });

        // 3. Apply the security requirement globally to all CONTROLLERS' endpoints
        options.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        //What it is:
                        //is an enumeration value used to indicate that a $ref (reference) object
                        //  is pointing to a Security Scheme definition.

                        //What it is used for:
                        //When parsing or building OpenAPI documents programmatically
                        //(such as in .NET using Microsoft.OpenApi.Models),
                        //you use this type to reference security configurations
                        //(like Bearer tokens, OAuth2, or API keys)
                        //defined globally in the components/securitySchemes section.
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"  // Must exactly match the definition ID above in AddSecurityDefinition(...)
                    }
                },

                // initialization to specify that a security scheme applies globally
                //  to the entire API without requiring any specific OAuth2 scopes.

                // It tells OpenAPI: "Use this security scheme, but no specific scopes are needed/required
                //  to access this endpoint."
                new string[] { }  //or new List<string>()
            }
        });
    }
);

builder.Services.AddSingleton<MemoryCache>();

//********** Middleware pipeline Configurations *******************************
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
