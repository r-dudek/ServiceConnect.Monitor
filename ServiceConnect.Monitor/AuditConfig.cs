using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using Microsoft.AspNet.SignalR;
using Microsoft.Owin.Cors;
using Owin;
using ServiceConnect.Monitor.SmExtensions;
using StructureMap;

namespace ServiceConnect.Monitor
{
    public class AuditConfig
    {
        private static IContainer _container;

        public AuditConfig(IContainer container)
        {
            _container = container;
        }

        public void Configuration(IAppBuilder app)
        {
            app.Map("/signalr", map =>
            {
                map.UseCors(CorsOptions.AllowAll);
                var hubConfiguration = new HubConfiguration();
                map.RunSignalR(hubConfiguration);
            });

            var httpConfig = new HttpConfiguration();
            httpConfig.EnableCors(new EnableCorsAttribute("*", "*", "*"));
            httpConfig.MessageHandlers.Add(new EnforceHttpsHandler());

            httpConfig.MapHttpAttributeRoutes();
            httpConfig.Routes.MapHttpRoute("Default", "{controller}/{action}", new { controller = "Home", action = "Index" });
            httpConfig.DependencyResolver = new StructureMapWebApiDependencyResolver(_container);

            var appXmlType = httpConfig.Formatters.XmlFormatter.SupportedMediaTypes.FirstOrDefault(t => t.MediaType == "application/xml");
            httpConfig.Formatters.XmlFormatter.SupportedMediaTypes.Remove(appXmlType);

            app.UseWebApi(httpConfig);
        }
    }

    public class EnforceHttpsHandler : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri.Scheme != Uri.UriSchemeHttps)
                return Task<HttpResponseMessage>.Factory.StartNew((Func<HttpResponseMessage>)(() => new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = (HttpContent)new StringContent("HTTPS Required")
                }), cancellationToken);
            return base.SendAsync(request, cancellationToken);
        }
    }

    public class CorsHeaderHandler : DelegatingHandler
    {
        private const string Origin = "Origin";
        private const string AccessControlRequestMethod = "Access-Control-Request-Method";
        private const string AccessControlRequestHeaders = "Access-Control-Request-Headers";
        private const string AccessControlAllowOrigin = "Access-Control-Allow-Origin";
        private const string AccessControlAllowMethods = "Access-Control-Allow-Methods";
        private const string AccessControlAllowHeaders = "Access-Control-Allow-Headers";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var isCorsRequest = request.Headers.Contains(Origin);
            var isPreflightRequest = request.Method == HttpMethod.Options;

            if (isCorsRequest)
            {
                if (isPreflightRequest)
                {
                    return Task.Factory.StartNew(() =>
                    {
                        var response = new HttpResponseMessage(HttpStatusCode.OK);
                        response.Headers.Add(AccessControlAllowOrigin, request.Headers.GetValues(Origin).First());

                        var currentAccessControlRequestMethod = request.Headers.GetValues(AccessControlRequestMethod).FirstOrDefault();

                        if (currentAccessControlRequestMethod != null)
                        {
                            response.Headers.Add(AccessControlAllowMethods, currentAccessControlRequestMethod);
                        }

                        var requestedHeaders = string.Join(", ", request.Headers.GetValues(AccessControlRequestHeaders));

                        if (!string.IsNullOrEmpty(requestedHeaders))
                        {
                            response.Headers.Add(AccessControlAllowHeaders, requestedHeaders);
                        }

                        return response;
                    }, cancellationToken);
                }

                return base.SendAsync(request, cancellationToken).ContinueWith(t =>
                {
                    var resp = t.Result;
                    resp.Headers.Add(AccessControlAllowOrigin, request.Headers.GetValues(Origin).First());
                    return resp;

                }, cancellationToken);
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}