package com.kiro.security.scanners;

import com.kiro.security.core.*;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.*;

/**
 * Infrastructure Config Scanner — analyzes Terraform (.tf), CloudFormation
 * (YAML/JSON), and Kubernetes manifests for security misconfigurations.
 */
public class InfraScanner implements BaseScanner {

    private final List<ScanRule> terraformRules = buildTerraformRules();
    private final List<ScanRule> cfnRules = buildCloudFormationRules();
    private final List<ScanRule> k8sRules = buildKubernetesRules();

    @Override
    public String getName() { return "Infrastructure Scanner"; }

    @Override
    public String getCategory() { return "infrastructure"; }

    @Override
    public List<Finding> scan(Path targetDir) throws Exception {
        List<Finding> findings = new ArrayList<>();

        // Terraform files
        for (Path tf : findByExtension(targetDir, ".tf")) {
            String rel = targetDir.relativize(tf).toString();
            try {
                String content = Files.readString(tf);
                findings.addAll(scanLines(content, rel, terraformRules, "TF"));
                findings.addAll(terraformMultiLineChecks(content, rel));
            } catch (IOException e) { /* skip */ }
        }

        // YAML files — CloudFormation and Kubernetes
        for (Path yf : findByExtensions(targetDir, Set.of(".yml", ".yaml"))) {
            String name = yf.getFileName().toString().toLowerCase();
            if (name.startsWith("docker-compose")) continue; // handled by ContainerScanner
            String rel = targetDir.relativize(yf).toString();
            try {
                String content = Files.readString(yf);
                if (content.contains("AWSTemplateFormatVersion") || content.contains("AWS::")) {
                    findings.addAll(scanLines(content, rel, cfnRules, "CFN"));
                }
                if (content.contains("apiVersion:") && content.contains("kind:")) {
                    findings.addAll(scanLines(content, rel, k8sRules, "K8S"));
                }
            } catch (IOException e) { /* skip */ }
        }

        return findings;
    }

    private List<Finding> scanLines(String content, String file, List<ScanRule> rules, String prefix) {
        List<Finding> findings = new ArrayList<>();
        String[] lines = content.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            for (ScanRule rule : rules) {
                if (rule.pattern().matcher(line).find()) {
                    findings.add(Finding.builder()
                            .id("%s-%s-%s-%d".formatted(prefix, rule.id(), file, i + 1))
                            .title(rule.title()).description(rule.description())
                            .severity(rule.severity()).category("infrastructure").subcategory(rule.subcategory())
                            .file(file).line(i + 1).snippet(line.trim())
                            .remediation(rule.remediation()).references(rule.references())
                            .cweId(rule.cweId()).businessImpact(rule.businessImpact()).confidence(rule.confidence())
                            .build());
                }
            }
        }
        return findings;
    }

    private List<Finding> terraformMultiLineChecks(String content, String file) {
        List<Finding> findings = new ArrayList<>();

        // S3 bucket without encryption
        Pattern s3Pattern = Pattern.compile("resource\\s+\"aws_s3_bucket\"\\s+\"[^\"]+\"\\s*\\{[^}]*\\}", Pattern.DOTALL);
        Matcher s3m = s3Pattern.matcher(content);
        while (s3m.find()) {
            if (!content.contains("aws_s3_bucket_server_side_encryption") && !s3m.group().contains("server_side_encryption")) {
                String firstLine = s3m.group().split("\n")[0].trim();
                findings.add(Finding.builder()
                        .id("TF-S3ENC-%s".formatted(file))
                        .title("S3 Bucket Without Encryption")
                        .description("S3 bucket does not have server-side encryption configured. Data at rest should always be encrypted.")
                        .severity(Severity.HIGH).category("infrastructure").subcategory("encryption")
                        .file(file).snippet(firstLine)
                        .remediation("Add an aws_s3_bucket_server_side_encryption_configuration resource with sse_algorithm = \"aws:kms\".")
                        .references(List.of("https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration"))
                        .cweId("CWE-311").businessImpact(BusinessImpact.HIGH).confidence(Confidence.MEDIUM)
                        .build());
            }
        }

        // RDS without encryption
        Pattern rdsPattern = Pattern.compile("resource\\s+\"aws_db_instance\"\\s+\"[^\"]+\"\\s*\\{[^}]*\\}", Pattern.DOTALL);
        Matcher rdsm = rdsPattern.matcher(content);
        while (rdsm.find()) {
            String block = rdsm.group();
            if (!block.contains("storage_encrypted") || block.contains("storage_encrypted = false")) {
                String firstLine = block.split("\n")[0].trim();
                findings.add(Finding.builder()
                        .id("TF-RDSENC-%s".formatted(file))
                        .title("RDS Instance Without Encryption")
                        .description("RDS database instance does not have storage encryption enabled.")
                        .severity(Severity.HIGH).category("infrastructure").subcategory("encryption")
                        .file(file).snippet(firstLine)
                        .remediation("Add storage_encrypted = true to the aws_db_instance resource.")
                        .references(List.of("https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#storage_encrypted"))
                        .cweId("CWE-311").businessImpact(BusinessImpact.CRITICAL).confidence(Confidence.HIGH)
                        .build());
            }
        }

        return findings;
    }

    private List<Path> findByExtension(Path targetDir, String ext) throws IOException {
        return findByExtensions(targetDir, Set.of(ext));
    }

    private List<Path> findByExtensions(Path targetDir, Set<String> extensions) throws IOException {
        List<Path> matches = new ArrayList<>();
        Files.walkFileTree(targetDir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String name = dir.getFileName().toString();
                if (Set.of("node_modules", ".git", ".terraform", "target").contains(name)) return FileVisitResult.SKIP_SUBTREE;
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String name = file.getFileName().toString();
                int dot = name.lastIndexOf('.');
                if (dot >= 0 && extensions.contains(name.substring(dot))) {
                    matches.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return matches;
    }

    // --- Rule Definitions ---

    private static List<ScanRule> buildTerraformRules() {
        return List.of(
                new ScanRule("SG-001", "Security Group Open to World (0.0.0.0/0)",
                        "Security group ingress rule allows traffic from any IP address.",
                        "network-exposure", Pattern.compile("cidr_blocks\\s*=\\s*\\[\\s*\"0\\.0\\.0\\.0/0\"\\s*]"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-284",
                        "Restrict cidr_blocks to specific IP ranges or use security group references.",
                        List.of("https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule")),

                new ScanRule("SG-002", "IPv6 Security Group Open to World (::/0)",
                        "Security group allows IPv6 traffic from any address.",
                        "network-exposure", Pattern.compile("ipv6_cidr_blocks\\s*=\\s*\\[\\s*\"::/0\"\\s*]"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-284",
                        "Restrict IPv6 CIDR blocks to specific ranges.",
                        List.of("https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html")),

                new ScanRule("PUB-001", "Publicly Accessible Resource",
                        "Resource is configured as publicly accessible.",
                        "public-access", Pattern.compile("publicly_accessible\\s*=\\s*true"),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH, "CWE-284",
                        "Set publicly_accessible = false and use VPC endpoints or bastion hosts.",
                        List.of("https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html")),

                new ScanRule("LOG-001", "CloudTrail or Logging Disabled",
                        "Logging is explicitly disabled.",
                        "logging", Pattern.compile("enable_logging\\s*=\\s*false|logging\\s*\\{\\s*enabled\\s*=\\s*false"),
                        Severity.MEDIUM, BusinessImpact.HIGH, Confidence.HIGH, "CWE-778",
                        "Enable logging for all infrastructure resources.",
                        List.of("https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html")),

                new ScanRule("ENC-001", "Encryption Disabled",
                        "Resource has encryption explicitly disabled.",
                        "encryption", Pattern.compile("encrypted\\s*=\\s*false|storage_encrypted\\s*=\\s*false|kms_key_id\\s*=\\s*\"\""),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH, "CWE-311",
                        "Enable encryption and specify a KMS key.",
                        List.of("https://docs.aws.amazon.com/kms/latest/developerguide/overview.html"))
        );
    }

    private static List<ScanRule> buildCloudFormationRules() {
        return List.of(
                new ScanRule("SG-001", "Security Group Open to World",
                        "CloudFormation security group allows inbound access from 0.0.0.0/0.",
                        "network-exposure", Pattern.compile("CidrIp\\s*:\\s*[\"']?0\\.0\\.0\\.0/0"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-284",
                        "Restrict CidrIp to specific IP ranges.",
                        List.of("https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-rule.html")),

                new ScanRule("S3-001", "S3 Bucket with Public ACL",
                        "S3 bucket is configured with a public access control list.",
                        "public-access", Pattern.compile("(?i)AccessControl\\s*:\\s*[\"']?(?:PublicRead|PublicReadWrite)"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-284",
                        "Remove public ACLs. Use bucket policies and enable S3 Block Public Access.",
                        List.of("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html")),

                new ScanRule("IAM-001", "IAM Policy with Wildcard Actions",
                        "IAM policy grants wildcard (*) actions, violating the principle of least privilege.",
                        "iam", Pattern.compile("Action\\s*:\\s*[\"']?\\*"),
                        Severity.HIGH, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-250",
                        "Replace wildcard actions with specific permissions.",
                        List.of("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"))
        );
    }

    private static List<ScanRule> buildKubernetesRules() {
        return List.of(
                new ScanRule("SEC-001", "Privileged Container in K8s",
                        "Kubernetes pod is configured to run as privileged.",
                        "privilege-escalation", Pattern.compile("privileged\\s*:\\s*true"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-250",
                        "Set privileged: false. Use specific capabilities via securityContext.capabilities.add.",
                        List.of("https://kubernetes.io/docs/tasks/configure-pod-container/security-context/")),

                new ScanRule("SEC-002", "Container Running as Root",
                        "Kubernetes container is configured to run as root (runAsUser: 0).",
                        "privilege-escalation", Pattern.compile("runAsUser\\s*:\\s*0\\b"),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH, "CWE-250",
                        "Set runAsUser to a non-root UID (e.g., 1000) and add runAsNonRoot: true.",
                        List.of("https://kubernetes.io/docs/tasks/configure-pod-container/security-context/")),

                new ScanRule("SEC-003", "hostNetwork Enabled",
                        "Pod uses the host network namespace, bypassing Kubernetes network isolation.",
                        "network-exposure", Pattern.compile("hostNetwork\\s*:\\s*true"),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH, "CWE-668",
                        "Set hostNetwork: false. Use Kubernetes Services and NetworkPolicies.",
                        List.of("https://kubernetes.io/docs/concepts/security/pod-security-standards/")),

                new ScanRule("IMG-001", "Container Image Using :latest Tag",
                        "Using :latest tag makes deployments non-deterministic and harder to audit.",
                        "best-practice", Pattern.compile("image\\s*:\\s*[\"']?[^\"'\\s]+:latest"),
                        Severity.MEDIUM, BusinessImpact.MEDIUM, Confidence.HIGH, "CWE-829",
                        "Pin container images to specific version tags or digests.",
                        List.of("https://kubernetes.io/docs/concepts/containers/images/"))
        );
    }
}
