using System.Data.SqlClient;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;

class Vulnerable
{
    void Run(string cmd) { Process.Start(cmd); }
    void Load() { var formatter = new BinaryFormatter(); }
    void Find(string id) { var command = new SqlCommand($"SELECT * FROM users WHERE id = {id}"); }
}
