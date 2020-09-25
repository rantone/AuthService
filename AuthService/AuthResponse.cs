using System;

namespace AuthService
{
    public class AuthResponse
    {
        public bool WasSuccessful { get; set; }
        public string Message { get; set; }
        public Session Session { get; set; }
        public User User { get; set; }
        public string AuthServiceVersion { get; } = "1.1.0";
    }
}
