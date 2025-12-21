using Newtonsoft.Json;
using Serilog;
using Polly;
using AutoMapper;

public class User
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserDto
{
    public string Name { get; set; }
}

class Program
{
    static void Main(string[] args)
    {
        while (true)
        {
            // 1. Serilog
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();
            
            Log.Information("Hello World from .NET!");

            // 2. Newtonsoft.Json
            var user = new User { Name = "James Bond", Email = "james.bond@mi6.gov.uk" };
            string json = JsonConvert.SerializeObject(user, Formatting.Indented);
            Console.WriteLine(json);

            // 3. AutoMapper
            var config = new MapperConfiguration(cfg => cfg.CreateMap<User, UserDto>());
            var mapper = config.CreateMapper();
            var dto = mapper.Map<UserDto>(user);
            Console.WriteLine($"Mapped DTO Name: {dto.Name}");

            // 4. Polly
            var policy = Policy
                .Handle<Exception>()
                .Retry(3, (exception, retryCount) =>
                {
                    Console.WriteLine($"Retry {retryCount} due to {exception.Message}");
                });

            try
            {
                policy.Execute(() =>
                {
                    if (new Random().Next(0, 2) == 0) throw new Exception("Random failure");
                    Console.WriteLine("Operation succeeded");
                });
            }
            catch (Exception)
            {
                Console.WriteLine("Operation failed after retries");
            }

            Thread.Sleep(5000);
        }
    }
}
