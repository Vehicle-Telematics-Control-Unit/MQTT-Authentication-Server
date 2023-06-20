﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MQTT_Authentication_Server.Models;
using Org.BouncyCastle.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MQTT_Authentication_Server.Data
{
    public class BaseController : ControllerBase
    {
        protected readonly UserManager<IdentityUser> userManager;
        protected readonly TCUContext tcuContext;
        protected readonly IConfiguration _config;
        protected const int MIN_OTP_LENGTH = 1000;
        protected const int MAX_OTP_LENGTH = 10000;
        public BaseController(TCUContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
        }

        protected JwtSecurityToken GenerateJwtToken(List<Claim> authClaims)
        {
            if (_config["JWT:Secret"] == null)
                throw new MissingFieldException("Failed to load JWT secret key");
            string? secretKey = _config["JWT:Secret"] ?? throw new MissingFieldException("Failed to load JWT secret key");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var token = new JwtSecurityToken(
                issuer: _config["JWT:ValidIssuer"],
                audience: _config["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }


        protected async Task<IdentityUser> FindUser(string? userIdentifier)
        {
            var user = await userManager.FindByNameAsync(userIdentifier);
            user ??= await userManager.FindByEmailAsync(userIdentifier);
            return user;
        }

        protected async Task<List<Claim>> GetUserClaims(IdentityUser user)
        {
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

            var userRoles = await userManager.GetRolesAsync(user);

            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            return claims;
        }

        protected async static Task<byte[]> ParseIformFile(IFormFile file)
        {
            using var reader = file.OpenReadStream();
            byte[] bytes = new byte[file.Length];
            await reader.ReadAsync(bytes.AsMemory(0, (int)file.Length));
            return bytes;
        }

        protected static string? ResolveIPAddress(HttpContext httpContext)
        {
            string? ipAddress = null;
            if (httpContext.Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                ipAddress = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            }
            else
            {
                var ipObj = httpContext.Connection.RemoteIpAddress;
                if (ipObj != null)
                    ipAddress = ipObj.ToString();
            }
            return ipAddress;
        }


        protected static byte[] GenerateHashBytes()
        {
            var digestor = DigestUtilities.GetDigest("SHA256");
            byte[] challenge = new byte[digestor.GetDigestSize()];
            SecureRandom secureRandom = new();
            secureRandom.NextBytes(challenge);
            digestor.BlockUpdate(challenge, 0, challenge.Length);
            digestor.DoFinal(challenge, 0);
            return challenge;
        }

        protected static string GenerateRandomString()
        {
            byte[] randomBytes = GenerateHashBytes();
            return Convert.ToBase64String(randomBytes);
        }


    }
}
