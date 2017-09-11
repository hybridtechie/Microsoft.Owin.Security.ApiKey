using System;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.ApiKey.Contexts;
using Microsoft.Owin.Security.Infrastructure;

namespace Microsoft.Owin.Security.ApiKey
{
    internal class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            string authorizationHeader = this.Request.Headers.Get(this.Options.Header);

            if (!String.IsNullOrWhiteSpace(authorizationHeader))
            {
                if (Options.HeaderKeyArray == null && Options.HeaderKey!=null)
                {
                    Options.HeaderKeyArray = new[] {Options.HeaderKey};
                }
                if (Options.HeaderKeyArray != null && Options.HeaderKeyArray.Length > 0)
                {
                    var headerKeyFound = false;
                    foreach (var headerKey in this.Options.HeaderKeyArray)
                    {
                        if (authorizationHeader.StartsWith(headerKey, StringComparison.OrdinalIgnoreCase))
                        {
                            headerKeyFound = true;
                            string apiKey = authorizationHeader.Substring(headerKey.Length).Trim();
                            if (!string.IsNullOrEmpty(apiKey))
                            {
                                var context = new ApiKeyValidateIdentityContext(this.Context, this.Options, apiKey);

                                await this.Options.Provider.ValidateIdentity(context);

                                if (context.IsValidated)
                                {
                                    var claims =
                                        await this.Options.Provider.GenerateClaims(
                                            new ApiKeyGenerateClaimsContext(this.Context, this.Options, apiKey));

                                    var identity = new ClaimsIdentity(claims, this.Options.AuthenticationType);

                                    return new AuthenticationTicket(identity, new AuthenticationProperties()
                                    {
                                        IssuedUtc = DateTime.UtcNow
                                    });
                                }
                            }
                            else
                            {
                                throw new ArgumentNullException(nameof(Options.HeaderKey),"ApiKey not found");
                            }
                        }
                    }
                    if (!headerKeyFound)
                    {
                        throw new InvalidCredentialException("Header Key Not Supported");
                    }
                }
                else
                {
                    throw new ArgumentNullException(nameof(Options.HeaderKey), "No Header Key( eg: Apikey) Found.");
                }
            }
            else
            {
                throw new ArgumentNullException(nameof(authorizationHeader), "Authorization Header not found.");
            }

            return null;
        }
    }
}