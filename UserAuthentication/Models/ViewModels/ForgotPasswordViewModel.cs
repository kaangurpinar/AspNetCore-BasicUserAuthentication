using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        public string Email { get; set; }
    }
}
