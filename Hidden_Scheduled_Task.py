from lib.cuckoo.common.abstracts import Signature

class HiddenScheduledTask(Signature):
    name = "Hidden_Scheduled_Task"
    description = "Hidden Scheduled Task"
    severity = 3
    categories = ["stealth"]
    authors = ["Misaki"]
    minimum = "1.3"
    references = ["https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/"]
    ttps = ["T1053.005", "T1070"]

    def run(self): 
        registry_indicator  = [
            r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\.*\\SD'
        ]

        for indicator in registry_indicator: 
            matched = self.check_delete_key(pattern=indicator, regex=True)
            if matched: 
                self.data.append({"deleted_task": matched})

        return self.has_matches() 