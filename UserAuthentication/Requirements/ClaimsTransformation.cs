using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using UserAuthentication.Models;

namespace UserAuthentication.Requirements
{
    public class ClaimsTransformation : IClaimsTransformation
    {
        private readonly UserManager<AppUser> _userManager;

        public ClaimsTransformation(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var identity = principal.Identity as ClaimsIdentity;

            var user = await _userManager.FindByNameAsync(identity.Name);

            if (user != null)
            {
                if(!principal.HasClaim(c => c.Type == ClaimTypes.DateOfBirth))
                {
                    var dateOfBirthClaim = new Claim(ClaimTypes.DateOfBirth, user.BirthDay.ToShortDateString());

                    identity.AddClaim(dateOfBirthClaim);
                }
            }

            return principal;
        }
    }
}
