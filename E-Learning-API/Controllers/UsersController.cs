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
using Microsoft.EntityFrameworkCore;
using NETCore.MailKit.Core;
using E_Learning_API.Extensions;
using Microsoft.AspNetCore.WebUtilities;

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
        private readonly IEmailService emailService;
        private readonly ELearningDbContext dbContext;
        private readonly TokenValidationParameters tokenValidationParameters;

        public UsersController(
            SignInManager<AppUser> signInManager,
            UserManager<AppUser> userManager,
            ILoggerService logger,
            IConfiguration config,
            IEmailService emailService,
            ELearningDbContext dbContext,
            TokenValidationParameters tokenValidationParameters)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.logger = logger;
            this.config = config;
            this.emailService = emailService;
            this.dbContext = dbContext;
            this.tokenValidationParameters = tokenValidationParameters;
        }


        /// <summary>
        /// User Register
        /// </summary>
        /// <param name="userRegisterDTO"></param>
        /// <returns></returns>
        [Route("register")]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] UserRegisterDTO userRegisterDTO)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                var firstname = userRegisterDTO.FirstName;
                var lastname = userRegisterDTO.LastName;
                var username = userRegisterDTO.UserName;
                var password = userRegisterDTO.Password;

                var user = new AppUser { FirstName = firstname, LastName = lastname, Email = username, UserName = username };
                var result = await userManager.CreateAsync(user, password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Student");

                    // Sending Confirmation Email
                    var confirmEmailToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
                    var encodedEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);
                    var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

                    var confirmationLink = $"{HttpContext.GetAppUrl()}/api/Users/ConfirmEmail?UserId={user.Id}&Code={validEmailToken}";

                    // here Url.Action method is not adding "ConfirmEmail" action name to link. so, I used different way to solve it
                    //var confirmationLink = Url.Action(nameof(ConfirmEmail), "Users", new { UserId = user.Id, Code = code }, Request.Scheme, Request.Host.ToString());

                    await emailService.SendAsync(user.Email, "Confirm Your Email", $"Please confirm your e-mail by clicking this link: <a href=\"{confirmationLink}\">click here</a>", true);

                    return Ok(new { result.Succeeded });
                }

                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        logger.LogError($"{errLocation}: {error.Code} {error.Description}");
                    }
                    return ErrorHandler($"{errLocation}: {username} User Registration attempted failed.");
                }

                return BadRequest();
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation}: {ex.Message} - {ex.InnerException}");
            }
        }

        /// <summary>
        /// User Register
        /// </summary>
        /// <param name="UserId"></param>
        /// <param name="Code"></param>
        /// <returns></returns>
        //[Route("register")]
        [HttpGet("ConfirmEmail")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string UserId, string Code)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                var user = await userManager.FindByIdAsync(UserId);
                if (user != null)
                {
                    var encodedEmailToken = WebEncoders.Base64UrlDecode(Code);
                    var confirmEmailToken = Encoding.UTF8.GetString(encodedEmailToken);

                    var result = await userManager.ConfirmEmailAsync(user, confirmEmailToken);

                    if (!result.Succeeded)
                    {
                        foreach (var error in result.Errors)
                        {
                            logger.LogError($"{errLocation}: {error.Code} {error.Description}");
                        }
                        return ErrorHandler($"{errLocation}: {user.UserName} User email confirmation attempted failed.");
                    }

                    return Ok(new { message = "Your email has been confirmed" });
                }

                return BadRequest();
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

                var user = await userManager.FindByNameAsync(username);

                if (user != null)
                {
                    if (!await userManager.IsEmailConfirmedAsync(user))
                    {
                        logger.LogInfo($"{errLocation}: User has not confirmed email: {username}");

                        return Unauthorized(new { header = "Email Confirmation", errorMessage = "We sent you an Confirmation Email. Please Confirm Your Registration To Log in." });
                    }

                    logger.LogInfo($"{errLocation}: Login attempt from user {username}");
                    var result = await signInManager.PasswordSignInAsync(username, password, false, false);

                    if (result.Succeeded)
                    {
                        logger.LogInfo($"{errLocation}: {username} successfully authenticated");
                        var userRoles = (await signInManager.UserManager.GetRolesAsync(user)).ToList();

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

                        return Ok(new { token = tokenString, refreshToken = newRefreshToken, username = user.UserName, roles = userRoles.Cast<object>().ToArray() });
                    }
                }
                

                logger.LogInfo($"{errLocation}: {username} not authenticated");
                return Unauthorized(userDTO);
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation}: {ex.Message} - {ex.InnerException}");
            }
        }
        
        /// <summary>
        /// User Login endpoint
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Route("ForgetPassword")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> ForgetPassword(string email)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                if (string.IsNullOrWhiteSpace(email))
                {
                    return BadRequest(email);
                }

                var user = await userManager.FindByEmailAsync(email);

                if (user != null)
                {
                    if (!await userManager.IsEmailConfirmedAsync(user))
                    {
                        logger.LogInfo($"{errLocation}: User has not confirmed email: {email}");

                        return Unauthorized(new { header = "Email Confirmation", errorMessage = "We sent you an Confirmation Email. Please Confirm Your Registration To Log in." });
                    }

                    var pwdResetToken = await userManager.GeneratePasswordResetTokenAsync(user);
                    var encodedPwdResetToken = Encoding.UTF8.GetBytes(pwdResetToken);
                    var validPwdResetToken = WebEncoders.Base64UrlEncode(encodedPwdResetToken);

                    var url = $"{HttpContext.GetAppUrl()}/api/Users/ForgetPassword?email={user.Id}&token={validPwdResetToken}";

                    await emailService.SendAsync(user.Email, "Reset Password", "<h1>Follow the instruction to reset your password</h1>" +
                        $"<p>To reset your password <a href=\"{url}\">click here</a></p>", true);

                    return Ok(new { message = "Success" });

                }

                logger.LogInfo($"{errLocation}: No user associated with {email}");
                return NotFound(new { message = "User Not Found" });
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
                var principal = GetPrincipalFromExpiredToken(refreshTokenDTO.Token);

                var username = principal.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = await userManager.FindByNameAsync(username);
                var userRoles = (await signInManager.UserManager.GetRolesAsync(user)).ToList();

                var refreshToken = dbContext.RefreshTokens.Where(rt => rt.UserId == user.Id).FirstOrDefault();

                if (refreshToken == null || refreshToken.Token != refreshTokenDTO.RefreshToken || refreshToken.ExpiryDate < DateTime.Now)
                {
                    return BadRequest();
                }

                var newJwtToken = await GenerateJSONWebToken(user);
                var newRefreshToken = GenerateRefreshToken();

                refreshToken.Token = newRefreshToken;
                refreshToken.ExpiryDate = DateTime.Now.AddMonths(6);

                await dbContext.SaveChangesAsync();

                return new ObjectResult(new 
                {
                    token = newJwtToken,
                    refreshToken = newRefreshToken,
                    username = user.UserName,
                    userRoles = userRoles.Cast<object>().ToArray()
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
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Email),
                new Claim("id", user.Id.ToString())
            };

            var roles = await userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(r => new Claim(ClaimsIdentity.DefaultRoleClaimType, r)));

            var token = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Issuer"],
                claims,
                null,
                expires: DateTime.Now.AddMinutes(1),
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

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if ((securityToken is not JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
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
