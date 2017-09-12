using System;
using System.Net;
using System.Security.Authentication;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Owin.Security.ApiKey.Web;
using Microsoft.Owin.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.ApiKey.Tests
{
    [TestClass]
    public class AuthenticationTests
    {
        private TestServer api;

        [TestInitialize]
        public void Initialize()
        {
            this.api = TestServer.Create<Startup>();
        }

        [TestCleanup]
        public void Cleanup()
        {
            this.api.Dispose();
        }

        [TestMethod]
        public async Task WebRequest_No_Authorization_Header_Should_Yield_ArgumentNullException()
        {
            try
            {
                await this.api.HttpClient.GetAsync("/api/values");
            }
            catch (Exception e)
            {
                e.Should().BeOfType<ArgumentNullException>();
            }

        }

        [TestMethod]
        public async Task WebRequest_No_HeaderKey_Should_Yield_ArgumentNullException()
        {
            try
            {
                await this.api.CreateRequest("/api/values").AddHeader("Authorization", null).GetAsync(); ;
            }
            catch (Exception e)
            {
                e.Should().BeOfType<ArgumentNullException>();
            }

        }

       [TestMethod]
        public async Task WebRequest_Wrong_HeaderKey_Should_Yield_InvalidCredentialsException()
        {
            try
            {
                await this.api.CreateRequest("/api/values").AddHeader("Authorization", "Bearer 1234").GetAsync(); ;
            }
            catch (Exception e)
            {
                e.Should().BeOfType<InvalidCredentialException>();
            }

        }

        [TestMethod]
        public async Task WebRequest_Empty_HeaderKey_Should_Yield_ArgumentNullException()
        {
            try
            {
                await this.api.CreateRequest("/api/values").AddHeader("Authorization", "").GetAsync(); ;
            }
            catch (Exception e)
            {
                e.Should().BeOfType<ArgumentNullException>();
            }

        }


        [TestMethod]
        public async Task WebRequest_ApiKey_Authentication_Should_Yield_200()
        {
            var response = await this.api.CreateRequest("/api/values").AddHeader("Authorization", "ApiKey 123")
                .GetAsync();
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            response = await this.api.CreateRequest("/api/values").AddHeader("Authorization", "123").GetAsync();
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}