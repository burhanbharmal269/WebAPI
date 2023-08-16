using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using TodoLibrary.DataAccess;
using TodoAPI.StartupConfig;

var builder = WebApplication.CreateBuilder(args);
builder.AddStandardServices();
builder.AddCustomServices();
builder.AddAuthServices();
builder.AddHealthCheckServices();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapHealthChecks("/health").AllowAnonymous();

app.Run();
