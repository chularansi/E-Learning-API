using E_Learning_API.Data;
using E_Learning_API.Data.Entities;
using E_Learning_API.DTO;
using E_Learning_API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace E_Learning_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly SignInManager<AppUser> signInManager;
        private readonly UserManager<AppUser> userManager;
        private readonly ILoggerService logger;
        private readonly IConfiguration config;
        private readonly ELearningDbContext dbContext;

        public UsersController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, ILoggerService logger, IConfiguration config, ELearningDbContext dbContext)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.logger = logger;
            this.config = config;
            this.dbContext = dbContext;
        }


        /// <summary>
        /// User Register
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        [Route("register")]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] UserDTO userDTO)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                var username = userDTO.UserName;
                var password = userDTO.Password;

                var user = new AppUser { Email = username, UserName = username };
                var result = await userManager.CreateAsync(user, password);

                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        logger.LogError($"{errLocation}: {error.Code} {error.Description}");
                    }
                    return ErrorHandler($"{errLocation}: {username} User Registration attempted failed.");
                }

                return Ok(new { result.Succeeded });
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation}: {ex.Message} - {ex.InnerException}");
            }
        }

        /// <summary>
        /// User Login endpoint
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        [Route("login")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] UserDTO userDTO)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                var username = userDTO.UserName;
                var password = userDTO.Password;

                logger.LogInfo($"{errLocation}: Login attempt from user {username}");
                var result = await signInManager.PasswordSignInAsync(username, password, false, false);

                if (result.Succeeded)
                {
                    logger.LogInfo($"{errLocation}: {username} successfully authenticated");
                    var user = await userManager.FindByNameAsync(username);
                    var tokenString = await GenerateJSONWebToken(user);

                    var newRefreshToken = GenerateRefreshToken();

                    var userRefreshToken = dbContext.RefreshTokens.Where(urt => urt.UserId == user.Id).FirstOrDefault();

                    if (userRefreshToken != null)
                    {
                        userRefreshToken.Token = newRefreshToken;
                        userRefreshToken.ExpiryDate = DateTime.Now.AddMonths(6);
                    }
                    else
                    {
                        var refreshToken = new RefreshToken
                        {
                            UserId = user.Id,
                            Token = newRefreshToken,
                            ExpiryDate = DateTime.Now.AddMonths(6)
                        };

                        dbContext.RefreshTokens.Add(refreshToken);
                    }

                    await dbContext.SaveChangesAsync();

                    return Ok(new { token = tokenString, refreshToken = newRefreshToken });
                }

                logger.LogInfo($"{errLocation}: {username} not authenticated");
                return Unauthorized(userDTO);
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation}: {ex.Message} - {ex.InnerException}");
            }
        }

        [Route("refreshToken")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDTO refreshTokenDTO)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                var principal = GetPrincipalFromExpiredToken(refreshTokenDTO.JwtToken);
                //var username = principal.Identity.Name;
                //var userId = principal.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier)
                //       .Select(c => c.Value).SingleOrDefault();

                var username = principal.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = await userManager.FindByNameAsync(username);

                var refreshToken = dbContext.RefreshTokens.Where(rt => rt.UserId == user.Id).FirstOrDefault();

                if (refreshToken == null || refreshToken.Token != refreshTokenDTO.RefreshToken || refreshToken.ExpiryDate < DateTime.Now)
                {
                    return BadRequest();
                }

                var newJwtToken = GenerateJSONWebToken(user);
                var newRefreshToken = GenerateRefreshToken();

                var userRefreshToken = dbContext.RefreshTokens.Where(urt => urt.UserId == user.Id).FirstOrDefault();

                userRefreshToken.Token = newRefreshToken;
                userRefreshToken.ExpiryDate = DateTime.Now.AddMonths(6);

                await dbContext.SaveChangesAsync();

                return new ObjectResult(new
                {
                    token = newJwtToken,
                    refreshToken = newRefreshToken
                });
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation}: {ex.Message} - {ex.InnerException}");
            }
        }

        [Route("revokeToken")]
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> RevokeRefreshToken()
        {
            var username = User.Identity.Name;

            var user = dbContext.AppUsers.SingleOrDefault(u => u.UserName == username);
            if (user == null) return BadRequest();

            var userRefreshToken = dbContext.RefreshTokens.Where(urt => urt.UserId == user.Id).FirstOrDefault();
            userRefreshToken.Token = null;

            await dbContext.SaveChangesAsync();

            return NoContent();
        }

        private async Task<string> GenerateJSONWebToken(AppUser user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                //new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.UserName)
            };

            var roles = await userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(r => new Claim(ClaimsIdentity.DefaultRoleClaimType, r)));

            var token = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Issuer"],
                claims,
                null,
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        //private string GenerateRefreshToken()
        //{
        //    var uniqueString = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString());
        //    var refreshToken = Convert.ToBase64String(uniqueString);

        //    return refreshToken;
        //}

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = config["Jwt:Issuer"],
                ValidAudience = config["Jwt:Issuer"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            //var jwtSecurityToken = securityToken as JwtSecurityToken;
            //if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            //    throw new SecurityTokenException("Invalid token");
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        private ObjectResult ErrorHandler(string message)
        {
            logger.LogError(message);
            return StatusCode(500, "Something went wrong, Please contact the Administrator");
        }

        private string GetControllerAndActionNames()
        {
            var controller = ControllerContext.ActionDescriptor.ControllerName;
            var action = ControllerContext.ActionDescriptor.ActionName;

            return $"{controller} - {action}";
        }
    }
}
