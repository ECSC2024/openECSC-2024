using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace RemoteDiagnostics.Contract
{
    [Flags]
    public enum PrivilegeAttributes : uint
    {
        Disabled = 0x00000000,
        EnabledByDefault = 0x00000001,
        Enabled = 0x00000002,
        Removed = 0x00000004,
        UsedForAccess = 0x80000000,
    }

    [DataContract]
    public class Privilege
    {
        [DataMember]
        public string Name;
        [DataMember]
        public PrivilegeAttributes Attributes;
    }

    [DataContract]
    public class GroupObject
    {
        [DataMember]
        public string Name { get; set; }

        [DataMember]
        public string Sid { get; set; }
    }

    [DataContract]
    public class ProcessSecurityObject
    {
        [DataMember]
        public string Name { get; set; }
        [DataMember]
        public string PrimarySid { get; set; }

        [DataMember]
        public GroupObject[] Groups { get; set; }

        [DataMember]
        public List<Privilege> Privileges { get; set; }
    }
}
