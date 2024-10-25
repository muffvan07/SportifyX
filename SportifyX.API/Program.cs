using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SportifyX.Application.Interfaces;
using SportifyX.Application.Services;
using SportifyX.Application.Services.Common;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.CrossCutting.ExceptionHandling;
using SportifyX.Domain.Interfaces;
using SportifyX.Domain.Settings;
using SportifyX.Infrastructure.Data;
using SportifyX.Infrastructure.Repositories;
using SportifyX.Infrastructure.Security;
using SportifyX.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Configuration settings for JWT
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));

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

// Register the JWT token generator
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register services and repositories
builder.Services.AddScoped<IApiLogService, ApiLogService>();
builder.Services.AddSingleton<LogQueue>(); // Register LogQueue as singleton

builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
builder.Services.AddScoped<IProductService, ProductService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddTransient<IEmailSenderService, EmailSenderService>();
builder.Services.AddTransient<ISmsSenderService, SmsSenderService>();

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

app.UseRouting();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.UseSwagger();

app.UseExceptionHandler("/error");

app.UseHsts();

app.Run();
