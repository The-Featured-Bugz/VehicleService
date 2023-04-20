using System;
using MongoDB.Bson;

namespace AuthService.Models
{
    public class User
    {
        public ObjectId Id { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }

        public User()
        {
        }
    }
}
