using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace UserAuthentication.Requirements
{
    public class MinimumAgeRequirement : IAuthorizationRequirement
    {
        public int MinimumAge { get; set; }

        public MinimumAgeRequirement(int minimumAge)
        {
            MinimumAge = minimumAge;
        }
    }

    public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
        {
            var dateOfBirthClaim = context.User.FindFirst(c => c.Type == ClaimTypes.DateOfBirth);
            if (dateOfBirthClaim != null)
            {
                var dateOfBirth = Convert.ToDateTime(dateOfBirthClaim.Value);
                var calculatedAge = DateTime.Now.Year - dateOfBirth.Year;

                if(calculatedAge >= requirement.MinimumAge)
                {
                    context.Succeed(requirement);
                }
                else
                {
                    context.Fail();
                }
            }
            return Task.CompletedTask;
        }
    }
}
