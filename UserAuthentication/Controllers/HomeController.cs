using Microsoft.AspNetCore.Mvc;

namespace UserAuthentication.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View();
        }

        public IActionResult AccessDenied(string returnUrl)
        {
            if (returnUrl.Contains("Profile"))
            {
                ViewBag.Message = "You must at least 21 years old to access this page.";
            }
            else
            {
                ViewBag.Message = "You don't have permission to access this page.";
            }

            return View();
        }
    }
}
