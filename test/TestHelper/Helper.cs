using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace TestHelper
{
    public static class Helper
    {
        public static int GetRandomNumber()
        {
            return new Random((int)DateTime.Now.Ticks).Next();
        }

        public static bool GetRandomBoolean()
        {
            return GetRandomNumber() % 200 > 100;
        }

        public static T GetFieldValueFromInstance<T>(string fieldName, bool isPublic, bool isStatic, object instance, bool inBaseClass = false)
        {
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            FieldInfo field = myType.GetField(fieldName, (isPublic ? BindingFlags.Public : BindingFlags.NonPublic)
                | (isStatic ? BindingFlags.Static : BindingFlags.Instance));

            try
            {
                return (T)Convert.ChangeType(field.GetValue(instance), typeof(T));
            }
            catch
            {
                return (T)field.GetValue(instance);
            }
        }

        public static void SetFieldValueToInstance<T>(string fieldName, bool isPublic, bool isStatic, object instance, object value, bool inBaseClass = false)
        {
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            FieldInfo field = myType.GetField(fieldName, (isPublic ? BindingFlags.Public : BindingFlags.NonPublic)
                | (isStatic ? BindingFlags.Static : BindingFlags.Instance));

            field.SetValue(instance, value);
        }

        public static T GetPropertyValueFromInstance<T>(string propertyName, bool isPublic, bool isStatic, object instance, bool inBaseClass = false)
        {
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            PropertyInfo property = myType.GetProperty(propertyName, (isPublic ? BindingFlags.Public : BindingFlags.NonPublic)
                | (isStatic ? BindingFlags.Static : BindingFlags.Instance));

            try
            {
                return (T)Convert.ChangeType(property.GetValue(instance), typeof(T));
            }
            catch
            {
                return (T)property.GetValue(instance);
            }
        }

        public static T GetStaticClassFieldValue<T>(string fieldName, Type classType, bool isPublic)
        {
            FieldInfo field = classType.GetField(fieldName, (isPublic ? BindingFlags.Public : BindingFlags.NonPublic)
                | BindingFlags.Static | BindingFlags.FlattenHierarchy);

            try
            {
                return (T)Convert.ChangeType(field.GetValue(null), typeof(T));
            }
            catch
            {
                return (T)field.GetValue(null);
            }
        }

        public static void SetPropertyValueToInstance<T>(string propertyName, bool isPublic, bool isStatic, object instance, object value, bool inBaseClass = false)
        {
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            PropertyInfo field = myType.GetProperty(propertyName, (isPublic ? BindingFlags.Public : BindingFlags.NonPublic)
                | (isStatic ? BindingFlags.Static : BindingFlags.Instance));

            field.SetValue(instance, value);
        }

        public static void SetPrivateRuntimeProperty(string propertyName, object instance, object value, bool inBaseClass = false)
        {
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            PropertyInfo privateProperty = myType.GetRuntimeProperties().Where(x => x.Name == propertyName).First();
            if (privateProperty != null)
            {
                privateProperty.SetValue(instance, value);
            }
        }

        public static void CallPrivateMethod<T>(string methodName, object instance, out T result, object[] parameters = null, bool inBaseClass = false)
        {
            if (parameters == null)
            {
                parameters = new object[] { };
            }
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            MethodInfo privateMethod = myType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
            if (privateMethod == null)
            {
                result = default(T);
            }
            else
            {
                result = (T)privateMethod.Invoke(instance, parameters);
            }
        }

        public static void CallPrivateMethodVoid(string methodName, object instance, object[] parameters = null, bool inBaseClass = false)
        {
            if (parameters == null)
            {
                parameters = new object[] { };
            }
            Type myType = inBaseClass
                ? instance.GetType().BaseType
                : instance.GetType();
            MethodInfo privateMethod = myType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
            privateMethod?.Invoke(instance, parameters);
        }

        public static string TCParameterValueStr(List<Tuple<string, string>> parameters, string key)
        {
            if (key == null)
            {
                return null;
            }

            foreach (var tuple in parameters)
            {
                if (key.Equals(tuple.Item1, StringComparison.OrdinalIgnoreCase))
                {
                    return tuple.Item2;
                }
            }
            return null;
        }

        public static int TCParameterValueInt(List<Tuple<string, string>> parameters, string key)
        {
            string Item2 = TCParameterValueStr(parameters, key);
            if (Item2 == null)
            {
                return -1;
            }

            if (int.TryParse(Item2, out int result))
            {
                return result;
            }

            return -2;
        }
    }
}
