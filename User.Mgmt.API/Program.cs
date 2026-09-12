using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using User.Mgmt.Service.Services;
using User.Mgmt.API.DataContext;
using User.Mgmt.Service.Models;

var builder = WebApplication.CreateBuilder(args);

//**********  services registration in the DI container. *******************************

//get DB connection string and register it
builder.Services.AddDbContext<AppDbDataContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DbConnStrng"));
});

//Adding Identity configuration and injecting IdentityUser, IdentityRole
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbDataContext>()
                .AddDefaultTokenProviders();

//adding Authentication configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
});

//email configuration
var emailConfig = builder.Configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig);

builder.Services.AddScoped<IEmailService, EmailService>();

// spcificied that EMAIL CONFIRMATION IS REQUIRED.
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//********** Middleware pipeline Configurations *******************************
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
