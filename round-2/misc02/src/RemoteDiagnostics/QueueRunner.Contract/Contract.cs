using Experimental.System.Messaging;
using Microsoft.Extensions.Configuration;

namespace QueueRunner.Contract
{
    public class Configuration
    {
        private static int _workers = -1;
        private static int _runtime = -1;
        private static string? _docker = null;
        private static string? _captchaKey = null;
        private static string? _queueName = null;
        private static IConfigurationRoot? _configuration { get; set; }

        public static void Load()
        {
            var builder = new ConfigurationBuilder()
                .AddJsonFile(@"C:\RemoteDiagnostics\config.json", optional: false);

            _configuration = builder.Build();
        }

        public static int Workers
        {
            get
            {
                if (_workers != -1) return _workers;

                if (_configuration == null)
                {
                    throw new Exception("Configuration not loaded");
                }
                _workers = _configuration.GetValue<int>("QueueSettings:Workers");
                return _workers;
            }
        }

        public static int Runtime
        {
            get
            {
                if (_runtime != -1) return _runtime;

                if (_configuration == null)
                {
                    throw new Exception("Configuration not loaded");
                }
                _runtime = _configuration.GetValue<int>("QueueSettings:Runtime");
                return _runtime;
            }
        }

        public static string Docker
        {
            get
            {
                if (_docker != null) return _docker;

                if (_configuration == null)
                {
                    throw new Exception("Configuration not loaded");
                }

                _docker = _configuration.GetValue<string>("Docker");

                if (_docker == null)
                {
                    throw new Exception("Docker path not configured");
                }

                return _docker;
            }
        }

        public static string? CaptchaKey
        {
            get
            {
                if (_captchaKey != null) return _captchaKey;

                if (_configuration == null)
                {
                    throw new Exception("Configuration not loaded");
                }

                _captchaKey = _configuration.GetValue<string>("CaptchaKey");

                return _captchaKey;
            }
        }

        public static string QueueName
        {
            get
            {
                if (_queueName != null) return _queueName;

                if (_configuration == null)
                {
                    throw new Exception("Configuration not loaded");
                }

                _queueName = string.Format(@".\private$\{0}", _configuration.GetValue<string?>("QueueSettings:QueueName") ?? "DiagnosticsRunnerQueue");

                return _queueName;
            }
        }
    }

    public class Queue
    {
        private static MessageQueue? _queue;

        private static string QueueName
        {
            get
            {
                return Configuration.QueueName;
            }
        }

        public static int GetEstimate(int position)
        {
            return position / Configuration.Workers * Configuration.Runtime;
        }

        private static MessageQueue Q
        {
            get
            {
                if (_queue == null)
                {
                    if (MessageQueue.Exists(QueueName))
                    {
                        _queue = new MessageQueue(QueueName);
                    }
                    else
                    {
                        _queue = MessageQueue.Create(QueueName);
                    }
                    _queue.Formatter = new XmlMessageFormatter(new Type[] { typeof(QueueItem) }); ;
                }
                return _queue;
            }
            set
            {
                _queue = value;
            }
        }

        public static int Count
        {
            get
            {
                var enumerator = Q.GetMessageEnumerator2();
                int count = 0;
                while (enumerator.MoveNext())
                {
                    count += 1;
                }
                return count;
            }
        }

        public static bool Exists(string endpoint)
        {
            var enumerator = Q.GetMessageEnumerator2();
            while (enumerator.MoveNext())
            {
                QueueItem queueItem = (QueueItem)enumerator.Current.Body;
                if (endpoint.Equals(queueItem.Endpoint))
                    return true;
            }
            return false;
        }

        public static QueueItem? Find(string id)
        {
            var enumerator = Q.GetMessageEnumerator2();
            var count = 0;
            QueueItem? queueItem = null;
            while (enumerator.MoveNext())
            {
                queueItem = (QueueItem)enumerator.Current.Body;
                if (id.Equals(queueItem.Id))
                {
                    break;
                }
                count += 1;
            }
            if (queueItem == null)
            {
                return null;
            }
            queueItem.Position = count;
            queueItem.EstimatedTime = GetEstimate(count);
            return queueItem;
        }

        public static QueueItem Create(string endpoint)
        {
            QueueItem queueItem = QueueItem.Create(endpoint);
            Q.Send(queueItem);
            return queueItem;
        }
        
        public static async Task<QueueItem> Receive()
        {
            Message message = await Task.Factory.FromAsync<Message>(
                       Q.BeginReceive(),
                       Q.EndReceive
            );

            return (QueueItem)message.Body;
        }
    }

    public class QueueItem
    {
        public string? Id { get; set; }
        public string? Endpoint { get; set; }
        public DateTime CreatedAt { get; set; }
        public int EstimatedTime { get; set; }
        public int Position { get; set; }
        public int Workers { get; set; }

        public static QueueItem Create(string endpoint)
        {
            int count = Queue.Count;
            return new QueueItem
            {
                Id = Guid.NewGuid().ToString(),
                Endpoint = endpoint,
                CreatedAt = DateTime.Now,
                Position = count,
                EstimatedTime = Queue.GetEstimate(count),
                Workers = Configuration.Workers
            };
        }
    }
}