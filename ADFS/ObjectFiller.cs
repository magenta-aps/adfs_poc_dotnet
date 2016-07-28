using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.IO;

namespace ADFS
{
    class ObjectFiller
    {
        public Dictionary<string, string> Load(string path)
        {
            var lines = File.ReadAllLines(path)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l))
                .Select(l => l.Split('=', ':').Select(w => w.Trim()).ToArray())
                .Where(l => l.Length == 2)
                .ToDictionary(l => l[0], l => l[1]);

            return lines;
        }

        public T Create<T>(string path) where T : new()
        {
            var lines = Load(path);
            return Create<T>(lines);
        }

        public T Create<T>(Dictionary<string, string> values) where T : new()
        {
            var target = new T();
            Fill(target, values);
            return target;
        }

        public void Fill(object target, Dictionary<string, string> values)
        {
            var targetType = target.GetType();
            foreach (var kvp in values)
            {
                var p = targetType.InvokeMember(kvp.Key, BindingFlags.SetProperty | BindingFlags.Public | BindingFlags.Instance, null, target, new object[] { kvp.Value });
            }
        }


    }
}
