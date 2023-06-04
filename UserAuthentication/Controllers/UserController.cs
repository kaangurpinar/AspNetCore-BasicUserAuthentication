using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using UserAuthentication.Models;
using UserAuthentication.Models.ViewModels;

namespace UserAuthentication.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<AppUser> _userManager;

        private readonly SignInManager<AppUser> _signInManager;

        private readonly RoleManager<AppRole> _roleManager;

        private readonly ILogger<UserController> _logger;

        public UserController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<AppRole> roleManager, ILogger<UserController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        [Authorize]
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel signUpViewModel)
        {
            if(ModelState.IsValid)
            {
                var user = new AppUser
                {
                    UserName = signUpViewModel.UserName,
                    Email = signUpViewModel.Email,
                    Gender = signUpViewModel.Gender,
                    BirthDay = signUpViewModel.BirthDay,
                    CreatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, signUpViewModel.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction("Login");
                }
                
                result.Errors.ToList().ForEach(error => { ModelState.AddModelError(string.Empty, error.Description); }); 
            }
            return View(signUpViewModel);
        }

        public IActionResult Login(string returnUrl)
        {
            TempData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(SignInViewModel signInViewModel)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(signInViewModel.UserName);

                if(user != null)
                {
                    await _signInManager.SignOutAsync();

                    var result = await _signInManager.PasswordSignInAsync(user, signInViewModel.Password, signInViewModel.RememberMe, true);

                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _userManager.SetLockoutEndDateAsync(user, null);
                        
                        var returnUrl = TempData["ReturnUrl"];

                        if(returnUrl != null)
                        {
                            return Redirect(returnUrl.ToString() ?? "/");
                        }

                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        await _userManager.AccessFailedAsync(user);

                        int failCount = await _userManager.GetAccessFailedCountAsync(user);

                        if (failCount == 3)
                        {
                            await _userManager.SetLockoutEndDateAsync(user, new DateTimeOffset(DateTime.Now.AddMinutes(1)));
                            ModelState.AddModelError(string.Empty, "This account has been locked for 1 minutes.");
                        }
                        else
                        {
                            if(result.IsLockedOut)
                            {
                                ModelState.AddModelError(string.Empty, "This account has been locked for 1 minutes.");
                            }
                            else
                            {
                                ModelState.AddModelError(string.Empty, "Incorrect username or password.");
                            }
                        }
                    }
                }
                ModelState.AddModelError(string.Empty, "Incorrect username or password.");
            }
            return View(signInViewModel);
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(forgotPasswordViewModel.Email);

                if (user != null)
                {
                    var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var link = Url.Action("ResetPassword", "User", new
                    {
                        userId = user.Id,
                        token = passwordResetToken
                    }, HttpContext.Request.Scheme);

                    _logger.LogInformation(link);

                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "User not found.");
                }
            }
            return View(forgotPasswordViewModel);
        }

        public IActionResult ResetPassword(string userId, string token)
        {
            return View(new ResetPasswordViewModel()
            {
                UserId = userId,
                Token = token
            });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetPasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(resetPasswordViewModel.UserId);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, resetPasswordViewModel.Token, resetPasswordViewModel.Password);
                    if (result.Succeeded)
                    {
                        await _userManager.UpdateSecurityStampAsync(user);

                        return RedirectToAction("Login", "User");
                    }
                    else
                    {
                        result.Errors.ToList().ForEach(error => ModelState.AddModelError(string.Empty, error.Description));
                    }
                }
                else{
                    ModelState.AddModelError(string.Empty, "User not found.");
                }
            }
            return View(resetPasswordViewModel);
        }

        [Authorize(Policy = "AtLeast21")]
        public async Task<IActionResult> Profile()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            if(user == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction("Index", "Home");
            }

            var profile = new EditProfileViewModel()
            {
                UserName = user.UserName,
                Email = user.Email,
                Gender = user.Gender,
                BirthDay = user.BirthDay,
                EmailConfirmed = user.EmailConfirmed
            };

            return View(profile);
        }

        [HttpPost]
        public async Task<IActionResult> Profile(EditProfileViewModel editProfileViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(User.Identity?.Name);

                if (user == null)
                {
                    await _signInManager.SignOutAsync();
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    if(user.UserName != editProfileViewModel.UserName && _userManager.Users.Any(n => n.UserName == editProfileViewModel.UserName))
                    {
                        ModelState.AddModelError(string.Empty, "Username is already in use.");
                    }
                    if (user.Email != editProfileViewModel.Email && _userManager.Users.Any(e => e.Email == editProfileViewModel.Email))
                    {
                        ModelState.AddModelError(string.Empty, "Email is already in use.");
                    }
                    user.UserName = editProfileViewModel.UserName;
                    user.Email = editProfileViewModel.Email;
                    user.Gender = editProfileViewModel.Gender;
                    user.BirthDay = editProfileViewModel.BirthDay;

                    var result = await _userManager.UpdateAsync(user);
                    if (result.Succeeded)
                    {
                        await _userManager.UpdateSecurityStampAsync(user);
                        await _signInManager.SignOutAsync();
                        await _signInManager.SignInAsync(user, true);

                        return RedirectToAction("Profile", "User");
                    }
                    result.Errors.ToList().ForEach(error => ModelState.AddModelError(string.Empty, error.Description));
                }
            }

            return View(editProfileViewModel);
        }

        public IActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel changePasswordViewModel)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(User.Identity.Name);

                var passwordIsValid = await _userManager.CheckPasswordAsync(user, changePasswordViewModel.Password);

                if (passwordIsValid)
                {
                    if (changePasswordViewModel.NewPassword != changePasswordViewModel.ConfirmNewPassword)
                    {
                        ModelState.AddModelError(string.Empty, "New Password do not match.");
                    }
                    else
                    {
                        var result = await _userManager.ChangePasswordAsync(user, changePasswordViewModel.Password, changePasswordViewModel.NewPassword);

                        if (result.Succeeded)
                        {
                            await _userManager.UpdateSecurityStampAsync(user);
                            await _signInManager.SignOutAsync();
                            await _signInManager.SignInAsync(user, isPersistent: true);

                            return RedirectToAction("Profile", "User");
                        }
                        result.Errors.ToList().ForEach(error => ModelState.AddModelError(string.Empty, error.Description));
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Password is invalid.");
                }
            }

            return View();
        }

        public async Task<IActionResult> ConfirmEmail()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            if (user == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var mailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var link = Url.Action("Confirmation", "User", new
            {
                userId = user.Id,
                token = mailToken
            }, HttpContext.Request.Scheme);

            _logger.LogInformation(link);

            return View();
        }

        public async Task<IActionResult> Confirmation(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if(user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if(result.Succeeded)
                {
                    return RedirectToAction("Profile", "User");
                }
            }
            return RedirectToAction("Index", "Home");
        }
    }
}
