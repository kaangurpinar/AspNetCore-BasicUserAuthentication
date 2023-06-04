using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models.ViewModels
{
    public class ResetPasswordViewModel
    {
        public string UserId { get; set; }

        public string Token { get; set; }

        public string Password { get; set; }
    }
}
