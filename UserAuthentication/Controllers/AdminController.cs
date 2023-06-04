using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserAuthentication.Models;
using UserAuthentication.Models.ViewModels;

namespace UserAuthentication.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<AppUser> _userManager;

        private readonly SignInManager<AppUser> _signInManager;

        private readonly RoleManager<AppRole> _roleManager;

        private readonly ILogger<AdminController> _logger;

        public AdminController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<AppRole> roleManager, ILogger<AdminController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = logger;
        }
    
        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Users()
        {
            var users = await _userManager.Users.ToListAsync();
            
            //var roles = _roleManager.Roles.ToList();

            var userViewModels = new List<UserViewModel>();

            foreach (var user in users)
            {
                var model = new UserViewModel()
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    Gender = user.Gender,
                    BirthDay = user.BirthDay,
                    CreatedAt = user.CreatedAt,
                    Roles = await _userManager.GetRolesAsync(user) as List<string> ?? new List<string>()
                };
                userViewModels.Add(model);
            }

            return View(userViewModels);
        }

        public async Task<IActionResult> Roles()
        {
            var roles = await _roleManager.Roles.ToListAsync();

            return View(roles);
        }

        public IActionResult Claims()
        {
            return View(User.Claims.ToList());
        }

        public IActionResult CreateRole()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(RoleViewModel roleViewModel)
        {
            var role = new AppRole()
            {
                Name = roleViewModel.Name,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _roleManager.CreateAsync(role);

            if (result.Succeeded)
            {
                return RedirectToAction("Roles");
            }

            return View(roleViewModel);
        }

        public async Task<IActionResult> EditRole(string id)
        {
            if(id == null)
            {
                return NotFound();
            }

            var role = await _roleManager.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id);

            if (role == null)
            {
                return NotFound();
            }

            var roleViewModel = new RoleViewModel()
            {
                Id = role.Id,
                Name = role.Name,
                CreatedAt = role.CreatedAt
            };

            return View(roleViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> EditRole(RoleViewModel roleViewModel)
        {
            if (ModelState.IsValid)
            {
                var role = await _roleManager.FindByIdAsync(roleViewModel.Id);

                if (role == null)
                {
                    return NotFound();
                }

                role.Name = roleViewModel.Name;

                var result = await _roleManager.UpdateAsync(role);

                if (result.Succeeded)
                {
                    return RedirectToAction("Roles");
                }
                result.Errors.ToList().ForEach(error => ModelState.AddModelError(string.Empty, error.Description));
            }
            return View(roleViewModel);
        }

        public async Task<IActionResult> DeleteRole(string id)
        {
            if(id == null)
            {
                return NotFound();
            }

            var role = await _roleManager.FindByIdAsync(id);

            var result = await _roleManager.DeleteAsync(role);

            if(result.Succeeded)
            {
                return RedirectToAction("Roles", "Admin");
            }

            return RedirectToAction("Roles", "Admin");
        }

        public async Task<IActionResult> EditUser(string id)
        {
            if (id == null)
            {
                return BadRequest();
            }

            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            var userViewModel = new UserViewModel()
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                BirthDay = user.BirthDay,
                Gender = user.Gender,
                CreatedAt = user.CreatedAt,
                Roles = await _userManager.GetRolesAsync(user) as List<string> ?? new List<string>()
            };

            return View(userViewModel);
        }

        public async Task<IActionResult> AssignRole(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            List<AppRole> roles = _roleManager.Roles.ToList();
            List<string> userRoles = await _userManager.GetRolesAsync(user) as List<string>;
            List<RoleViewModel> roleViewModels = new List<RoleViewModel>();
            roles.ForEach(role => roleViewModels.Add(new RoleViewModel()
            {
                Id = role.Id,
                Name = role.Name,
                HasRole = userRoles.Contains(role.Name)
            }));

            return View(roleViewModels);
        }

        [HttpPost]
        public async Task<IActionResult> AssignRole(List<RoleViewModel> roleViewModels, string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            foreach (var role in roleViewModels)
            {
                if(role.HasRole)
                {
                    await _userManager.AddToRoleAsync(user, role.Name);
                }
                else
                {
                    await _userManager.RemoveFromRoleAsync(user, role.Name);
                }
            }
            return RedirectToAction("Users");
        }
    }
}
