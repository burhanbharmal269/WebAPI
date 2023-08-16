﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TodoAPI.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration config;

    public AuthenticationController(IConfiguration config)
    {
        this.config = config;
    }

    public record AuthenticationData(string? UserName, string? Password);
    public record UserData(int Id, string FirstName, string LastName, string UserName);

    [HttpPost("token")]
    [AllowAnonymous]
    public ActionResult<string> Authenticate([FromBody] AuthenticationData data)
    {
        var user = ValidateCredentitals(data);

        if (user is null)
        {
            return Unauthorized();
        }
        string token = GenerateToken(user);
        TokenDetail tokenDetail = new TokenDetail()
        {
            token = token,
        };

        return Ok(tokenDetail);

    }

    private string GenerateToken(UserData user)
    {
        var secretKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.GetValue<string>("Authentication:SecretKey")));

        var singingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = new List<Claim>();
        claims.Add(new(JwtRegisteredClaimNames.Sub, user.Id.ToString()));
        claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.UserName));
        claims.Add(new(JwtRegisteredClaimNames.GivenName, user.FirstName));
        claims.Add(new(JwtRegisteredClaimNames.FamilyName, user.LastName));

        var token = new JwtSecurityToken(
            config.GetValue<string>("Authentication:Issuer"),
            config.GetValue<string>("Authentication:Audience"),
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(1),
            singingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);

    }

    private UserData? ValidateCredentitals(AuthenticationData data)
    {
        if (CompareValues(data.UserName, "Burhan") && CompareValues(data.Password, "Test123"))
        {
            return new UserData(1, "Burhan", "Bharmal", data.UserName!);
        }
        else if (CompareValues(data.UserName, "Darshit") && CompareValues(data.Password, "Test123"))
        {
            return new UserData(2, "Darshit", "Shah", data.UserName!);
        }
        return null;
    }
    private bool CompareValues(string? actual, string expected)
    {
        if (actual is not null)
        {
            if (actual.Equals(expected))
            {
                return true;
            }
        }
        return false;
    }

    public class TokenDetail
    {
        public string token { get; set; }
    }


}

