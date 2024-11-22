import json
from pathlib import Path
from packageurl import PackageURL
from lib4sbom.data.vulnerability import Vulnerability

class CSAFParser:

    def __init__(self):
        self.metadata = {}

    def parse_file(self, filename):
        self.filename = filename
        # Check file exists
        invalid_file = True
        if len(self.filename) > 0:
            # Check path
            filePath = Path(self.filename)
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                # Assume that processing can proceed
                invalid_file = False
        if invalid_file:
            raise FileNotFoundError
        self.data = json.load(open(self.filename))
        self.metadata={}
        self.product={}
        self.vulnerabilities=[]
        self._process_metadata()
        self._process_product()
        self._process_vulnerabilities()

    def _process_metadata(self):
        if len(self.data) == 0:
            return
        # Key attributes from the CSAF header

        document = self.data.get("document")
        if document is None:
            # Doesn't look like a CSAF document
            self.data = []
            return
        
        self.metadata["version"] = document["csaf_version"]
        self.metadata["title"] = document["title"]
        self.metadata["category"] = document["category"]
        self.metadata["date"] = document["tracking"]["current_release_date"]
        if "aggregate_severity" in document:
            self.metadata["severity"] = document["aggregate_severity"]["text"]
        if "notes" in document:
            notes = []
            for note in document["notes"]:
                note_ref = {'text' : note['text'], 'category': note['category']}
                if "title" in note:
                    note_ref['title']=note["title"]
                notes.append(note_ref)
            self.metadata["notes"] = notes
        if "publisher" in document:
            publisher_info = (
                f"{self.data['document']['publisher']['name']} "
                f"{self.data['document']['publisher']['namespace']}"
            )
            self.metadata["publisher"] = publisher_info
            self.metadata["author"] = self.data['document']['publisher']['name']
            self.metadata["author_url"] = self.data['document']['publisher']['namespace']
            if "contact_details" in self.data['document']['publisher']:
                self.metadata["contact_details"] = self.data['document']['publisher']['contact_details']
        if "tracking" in document:
            if "generator" in document["tracking"]:
                generator_version = "UNKNOWN"
                if (
                        "version"
                        in document["tracking"]["generator"]["engine"]
                ):
                    generator_version = document["tracking"]["generator"][
                        "engine"
                    ]["version"]
                self.metadata["generator"] = f"{self.data['document']['tracking']['generator']['engine']['name']} version {generator_version}"
            self.metadata["id"] = document["tracking"]["id"]
            self.metadata["initial_release_date"] = document["tracking"]["initial_release_date"]
            if "revision_history" in document["tracking"]:
                revision_data=[]
                for revision in document["tracking"]["revision_history"]:
                    revision_ref={'date' : revision["date"], 'number' : revision["number"], 'summary' : revision["summary"]}
                    revision_data.append(revision_ref)
                self.metadata["revision"] = revision_data
            self.metadata["tracking_status"] = document["tracking"]["status"]
            self.metadata["tracking_version"] = document["tracking"]["version"]
        if "references" in document:
            for reference in document["references"]:
                if "category" in reference:
                    self.metadata["reference_category"] = reference["category"]
                self.metadata["reference_url"] = reference["url"]
        if "distribution" in document:
            distribution_info = ""
            if "text" in document["distribution"]:
                distribution_info = f"{self.data['document']['distribution']['text']}"
            if "tlp" in document["distribution"]:
                distribution_info = (
                        distribution_info
                        + f" TLP: {self.data['document']['distribution']['tlp']['label']}"
                )
            self.metadata["distribution"] = distribution_info

    def _process_product(self):
        if len(self.data) == 0:
            return
        if "product_tree" not in self.data:
            return 
        product = self.data["product_tree"]
        for d in product["branches"]:
            element = {}
            self._process_branch(d, element)
        if "relationships" in product:
            self._process_product_relationships(product["relationships"])
    
    def _process_product_relationships(self, relationships):
        product_relationships = []
        for relationship in relationships:
            product_relationship = {}
            product_relationship["category"] = relationship.get("category", None)
            if "full_product_name" in relationship:
                product_relationship["product_id"] = relationship["full_product_name"].get("product_id", None)
                product_relationship["name"] = relationship["full_product_name"].get("name", None)
            product_relationship["product_reference"] = relationship.get("product_reference", None)
            product_relationship["relates_to_product_reference"] = relationship.get("relates_to_product_reference", None)
            product_relationships.append(product_relationship)
        self._process_product_relationships_into_product_id(product_relationships)

    def _process_product_relationships_into_product_id(self, product_relationships):
        for relationship in product_relationships:
            related_products = {}
            id = relationship["product_id"]
            product_reference = relationship["product_reference"]
            relates_to_product_reference = relationship["relates_to_product_reference"]
            if product_reference in self.product:
                product_details = self.product.get(product_reference, {})
                related_products["vendor"] = product_details.get("vendor", None)
                related_products["version"] = product_details.get("version", None)
            if relates_to_product_reference in self.product:
                product_details = self.product.get(relates_to_product_reference, {})
                related_products["product"] = product_details.get("product", None)
                related_products["family"] = product_details.get("family", None)
            if id is not None and id not in self.product:
                self.product[id] = related_products

    def _process_branch_element(self, branch_element, element):
        category = branch_element.get("category", None)
        name = branch_element.get("name", None)
        if category is not None:
            element[category] = name
        return element

    def _process_branch(self, branch_element, element):
        element = self._process_branch_element(branch_element, element)
        if "branches" in branch_element:
            for branch in branch_element["branches"]:
                element = self._process_branch(branch, element)
                if "product" in branch:
                    element["product_id"] = branch["product"]["product_id"]
                    if "product_identification_helper" in branch["product"]:
                        pid = branch["product"]["product_identification_helper"]
                        if "cpe" in pid:
                            # cpe format is: cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
                            cpe_info = pid["cpe"]
                            cpe_items = cpe_info.split(":")
                            # (cpe_items[1]) can have three value as /a,/h and /o
                            if cpe_items[1] in ["/a", "/o", "/h"]:
                                # Example is cpe:/a:redhat:rhel_eus:8.2::realtime
                                # some csaf will not have product version in cpe
                                # although this is not recommended by csaf 
                                element["product_version"] = cpe_items[4] if len(cpe_items) > 4 else None
                            elif cpe_items[1] == "2.3":
                                # Example is cpe:2.3:a:redhat:rhel_eus:8.2::realtime
                                element["product_version"] = cpe_items[5]
                        elif "purl" in pid:
                            # PURL format is: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>
                            # e.g. if "purl": "pkg:rpm/redhat/ruby@1.8.7.352-4.el6_2?arch=i686"
                            # version = 1.8.7.352-4.el6_2
                            purl_info = PackageURL.from_string(pid["purl"])
                            element["product_version"] = purl_info.to_dict()["version"]
                    item = {}
                    item["vendor"] = element.get("vendor", None)
                    item["product"] = element.get("product_name", "Not defined")
                    item["version"] = element.get("product_version", None)
                    if item["version"] is None:
                        item["version"] = element.get("product_version_range", None)
                    item["family"] = element.get("product_family", "")
                    id = element.get("product_id", None)
                    if id is not None and id not in self.product:
                        self.product[id] = item
                    # element = {}
        return element

    def _process_vulnerabilities(self):
        if len(self.data) == 0:
            return
        vuln_info = Vulnerability(validation="csaf")
        if "vulnerabilities" not in self.data:
            return 
        for vulnerability in self.data["vulnerabilities"]:
            vuln_info.initialise()
            if "cve" in vulnerability:
                vuln_info.set_id(vulnerability["cve"])
            if "title" in vulnerability:
                vuln_info.set_value("title", vulnerability["title"])
            if "cwe" in vulnerability:
                vuln_info.set_value("cwe",f"{vulnerability['cwe']['id']} - {vulnerability['cwe']['name']}")
            if "notes" in vulnerability:
                notes = []
                for note in vulnerability["notes"]:
                    note_ref = {'text' : note['text'], 'category': note['category']}
                    if "title" in note:
                        note_ref['title']=note["title"]
                    notes.append(note_ref)
                vuln_info.set_value("notes", notes)
            if "discovery_date" in vulnerability:
                vuln_info.set_value("discovery_date", vulnerability["discovery_date"])
            if "flags" in vulnerability:
                products = []
                for flag in vulnerability["flags"]:
                    if "label" in flag:
                        vuln_info.set_value("justification", flag["label"])
                    if "date" in flag:
                        vuln_info.set_value("created", flag["date"])
                    for product in flag["product_ids"]:
                        products.append(product)
                        vuln_info.set_value("product", products)
            if "ids" in vulnerability:
                for id in vulnerability["ids"]:
                    vuln_info.set_value("system_name", id["text"])
            if "references" in vulnerability:
                for reference in vulnerability["references"]:
                    vuln_info.set_value(reference["category"], [reference.get("summary",""), reference.get("url","")])
            if "release_date" in vulnerability:
                vuln_info.set_value("release_date", vulnerability["release_date"])
            if "threats" in vulnerability:
                for threat in vulnerability["threats"]:
                    vuln_info.set_value(threat["category"], threat["details"])
            if "product_status" in vulnerability:
                status = []
                for product_status in vulnerability["product_status"]:
                    status.append(product_status)
                    if "known_affected" in vulnerability["product_status"]:
                        known_affected_product_ids = []
                        known_affected = vulnerability["product_status"].get("known_affected", [])
                        for known_affected_product_id in known_affected:
                            known_affected_product_ids.append(known_affected_product_id)
                        vuln_info.set_value("known_affected_product_ids", known_affected_product_ids)
                    if "first_affected" in vulnerability["product_status"]:
                        first_affected_product_ids = []
                        first_affected = vulnerability["product_status"].get("first_affected", [])
                        for first_affected_product_id in first_affected:
                            first_affected_product_ids.append(first_affected_product_id)
                        vuln_info.set_value("first_affected_product_ids", first_affected_product_ids)
                    if "first_fixed" in vulnerability["product_status"]:
                        first_fixed_product_ids = []
                        first_fixed = vulnerability["product_status"].get("first_fixed", [])
                        for first_fixed_product_id in first_fixed:
                            first_fixed_product_ids.append(first_fixed_product_id)
                        vuln_info.set_value("first_fixed_product_ids", first_fixed_product_ids)
                    if "fixed" in vulnerability["product_status"]:
                        fixed_product_ids = []
                        fixed = vulnerability["product_status"].get("fixed", [])
                        for fixed_product_id in fixed:
                            fixed_product_ids.append(fixed_product_id)
                        vuln_info.set_value("fixed_product_ids", fixed_product_ids)
                    if "known_not_affected" in vulnerability["product_status"]:
                        known_not_affected_product_ids = []
                        known_not_affected = vulnerability["product_status"].get("known_not_affected", [])
                        for known_not_affected_product_id in known_not_affected:
                            known_not_affected_product_ids.append(known_not_affected_product_id)
                        vuln_info.set_value("known_not_affected_product_ids", known_not_affected_product_ids)
                    if "last_affected" in vulnerability["product_status"]:
                        last_affected_product_ids = []
                        last_affected = vulnerability["product_status"].get("last_affected", [])
                        for last_affected_product_id in last_affected:
                            last_affected_product_ids.append(last_affected_product_id)
                        vuln_info.set_value("last_affected_product_ids", last_affected_product_ids)
                    if "recommended" in vulnerability["product_status"]:
                        recommended_product_ids = []
                        recommended = vulnerability["product_status"].get("recommended", [])
                        for recommended_product_id in recommended:
                            recommended_product_ids.append(recommended_product_id)
                        vuln_info.set_value("recommended_product_ids", recommended_product_ids)
                    if "under_investigation" in vulnerability["product_status"]:
                        under_investigation_product_ids = []
                        under_investigation = vulnerability["product_status"].get("under_investigation", [])
                        for under_investigation_product_id in under_investigation:
                            under_investigation_product_ids.append(under_investigation_product_id)
                        vuln_info.set_value("under_investigation_product_ids", under_investigation_product_ids)
                vuln_info.set_value("status", status)
            if "remediations" in vulnerability:
                remediations = []
                for remediation in vulnerability["remediations"]:
                    remediation_ref = {'text': remediation['details'], 'category': remediation['category']}
                    if "date" in remediation:
                        remediation_ref['date'] = remediation['date']
                    if "entitlements" in remediation:
                        remediation_ref['entitlements'] = remediation['entitlements']
                    if "group_ids" in remediation:
                        remediation_ref['group_ids'] = remediation['group_ids']
                    if "product_ids" in remediation:
                        remediation_ref['product_ids'] = remediation['product_ids']
                    if "restart_required" in remediation:
                        remediation_ref['restart_required'] = remediation['restart_required']
                    if "url" in remediation:
                        remediation_ref['url'] = remediation['url']
                    remediations.append(remediation_ref)
                vuln_info.set_value("remediations", remediations)
            self.vulnerabilities.append(vuln_info.get_vulnerability())

    def get_metadata(self):
        return self.metadata

    def get_product(self):
        return self.product

    def get_vulnerabilities(self):
        return self.vulnerabilities

