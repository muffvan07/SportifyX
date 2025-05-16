using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
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
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Core framework services
builder.Services.AddControllers();

builder.Services.Configure<RouteOptions>(options => options.LowercaseUrls = true);

// 2. Configuration bindings
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<EmailSettingsSMTP>(builder.Configuration.GetSection("EmailSettingsSMTP"));
builder.Services.Configure<EmailSettingsApi>(builder.Configuration.GetSection("EmailSettingsApi"));
builder.Services.Configure<ApiSettings>(builder.Configuration.GetSection("ApiSettings"));

// 3. Authentication/Authorization
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
            ValidAudience = builder.Configuration["JwtSettings:Audience"],
            IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:SecretKey"]))
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    context.Response.Headers.Add("Token-Expired", "true");
                }

                return Task.CompletedTask;
            }
        };
    });

// 4. Database context
builder.Services.AddTransient<ApplicationDbContext>(_ =>
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

// 5. JSON options
builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.Converters.Add(new JsonDateTimeConverter());
});

// 6. Swagger/OpenAPI
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
            []
        }
    });
});

// 7. Dependency injection for services/repositories
builder.Services.AddScoped<IApiLogService, ApiLogService>();
builder.Services.AddSingleton<LogQueue>();
builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
builder.Services.AddScoped<IProductService, ProductService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IBrevoEmailService, BrevoEmailService>();
builder.Services.AddTransient<ISmsSenderService, SmsSenderService>();
builder.Services.AddScoped<IExceptionHandlingService, ExceptionHandlingService>();

// 8. HTTP client/accessor
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// 9. Middleware pipeline

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.DefaultModelsExpandDepth(-1); // Hides models from the Swagger UI
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SportifyX v1");
    });
    app.UseDeveloperExceptionPage();
}

app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<ApiLoggingMiddleware>();
app.UseMiddleware<JwtExpiryMiddleware>();
//app.UseMiddleware<ApiKeyMiddleware>();

app.UseRouting();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.UseSwagger();

app.UseExceptionHandler("/error");

app.UseHsts();

app.Run();
