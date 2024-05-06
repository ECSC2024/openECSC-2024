using Microsoft.AspNetCore.Mvc;
using QueueRunner.Contract;
using System.Text.RegularExpressions;

namespace QueueRunner.WebServer
{
    [Route("api/queue")]
    [ApiController]
    public partial class Controller : ControllerBase
    {
        private static HttpClient httpClient = new();

        [HttpGet("{id}")]
        public ActionResult<QueueItem> Get(string id)
        {
            QueueItem? queueItem = Queue.Find(id);
            if (queueItem == null)
            {
                return NotFound(new ErrorMessage("Not found in queue"));
            }
            return Ok(queueItem);
        }

        [HttpPost]
        public async Task<ActionResult<QueueItem>> Post([FromBody] CreateQueueItem newQueueItem)
        {
            // Validation
            string endpoint = newQueueItem.Endpoint.Trim();
            if (endpoint.Length > 255)
            {
                return BadRequest(new ErrorMessage("Endpoint too long (> 255 chars)"));
            }

            try
            {
                var rg = UrlRegex();
                if (rg.IsMatch(endpoint) == false)
                {
                    throw new Exception("Bad");
                }

                var uri = new Uri(string.Format("net.tcp://{0}/Diagnostics", endpoint));
                if (uri.Scheme != "net.tcp")
                {
                    throw new Exception("Bad");
                }
                if (uri.PathAndQuery != "/Diagnostics")
                {
                    throw new Exception("Bad");
                }
                endpoint = uri.Host;
                if (!uri.IsDefaultPort)
                {
                    endpoint += string.Format(":{0}", uri.Port);
                }
            }
            catch
            {
                return BadRequest(new ErrorMessage("Invalid endpoint. Use hostname[:port] or IP[:port]"));
            }

            string? captchaKey = Configuration.CaptchaKey;
            if (captchaKey != null)
            {
                try
                {
                    var form = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        { "secret", captchaKey },
                        { "response", newQueueItem.Captcha },
                    });
                    var response = await httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", form);
                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadFromJsonAsync<CaptchaResponse>();
                        if (result != null && result.Success == false)
                        {
                            return BadRequest(new ErrorMessage("Invalid captcha"));
                        }
                    }
                }
                catch {
                    // If we fail to check the captcha, we still allow users to proceed
                }
            }

            if (Queue.Exists(endpoint))
            {
                return BadRequest(new ErrorMessage("Endpoint is already queued"));
            }

            return Ok(Queue.Create(endpoint));
        }

        [GeneratedRegex(@"^[a-z0-9\-.]+(:[0-9]+)?$", RegexOptions.IgnoreCase, "en-GB")]
        private static partial Regex UrlRegex();
    }

    public class CreateQueueItem
    {
        public string Endpoint { set; get; }
        public string Captcha { set; get; }
    }

    public class CaptchaResponse
    {
        public bool Success { set; get; }
    }

    public class ErrorMessage
    {
        public string Error { set; get; }

        public ErrorMessage(string message)
        {
            Error = message;
        }
    }
}
