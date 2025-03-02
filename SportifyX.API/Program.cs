using AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using SportifyX.Application.Services;
using SportifyX.Application.Services.Common;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;
using SportifyX.Domain.Interfaces;
using SportifyX.Domain.Settings;
using SportifyX.Infrastructure.Data;
using SportifyX.Infrastructure.Middleware;
using SportifyX.Infrastructure.Repositories;
using SportifyX.Infrastructure.Security;
using SportifyX.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Configuration settings for JWT
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<EmailSettingsSMTP>(builder.Configuration.GetSection("EmailSettingsSMTP"));
builder.Services.Configure<EmailSettingsApi>(builder.Configuration.GetSection("EmailSettingsApi"));
builder.Services.Configure<ApiSettings>(builder.Configuration.GetSection("ApiSettings"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = ApiKeyDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = ApiKeyDefaults.AuthenticationScheme;
});

builder.Services.AddTransient<ApplicationDbContext>(provider =>
{
    var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
    optionsBuilder.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        option =>
        {
            option.EnableRetryOnFailure(5, TimeSpan.FromSeconds(10), null);
        });

    return new ApplicationDbContext(optionsBuilder.Options);
});

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];
var issuer = jwtSettings["Issuer"];
var audience = jwtSettings["Audience"];

// Configure default JSON DateTime format globally
builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.Converters.Add(new JsonDateTimeConverter());
});

// Register the JWT token generator
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SportifyX", Version = "v1" });

    // Define the API key security scheme
    c.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "X-API-KEY",
        Type = SecuritySchemeType.ApiKey,
        Description = "Enter Your API Key."
    });

    // Apply the security requirement globally
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            new string[] { }
        }
    });
});

// Register services and repositories
builder.Services.AddScoped<IApiLogService, ApiLogService>();
builder.Services.AddSingleton<LogQueue>(); // Register LogQueue as singleton

builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
builder.Services.AddScoped<IProductService, ProductService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IBrevoEmailService, BrevoEmailService>();
builder.Services.AddTransient<ISmsSenderService, SmsSenderService>();
builder.Services.AddScoped<IExceptionHandlingService, ExceptionHandlingService>();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();

    app.UseSwaggerUI(c =>
    {
        c.DefaultModelsExpandDepth(-1); // Hides models from the Swagger UI
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SportifyX v1"); // Adds a Swagger endpoint
    });

    app.UseDeveloperExceptionPage();
}

app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<ApiLoggingMiddleware>();
app.UseMiddleware<ApiKeyMiddleware>();

app.UseRouting();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.UseSwagger();

app.UseExceptionHandler("/error");

app.UseHsts();

app.Run();
