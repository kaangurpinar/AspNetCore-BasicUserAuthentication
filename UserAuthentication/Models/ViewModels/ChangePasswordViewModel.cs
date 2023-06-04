using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models.ViewModels
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string Password { get; set; }

        [Required]
        public string NewPassword { get; set; }

        [Required]
        public string ConfirmNewPassword { get; set;}
    }
}
