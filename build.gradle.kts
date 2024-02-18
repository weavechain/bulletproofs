import com.github.jk1.license.filter.DependencyFilter
import com.github.jk1.license.filter.LicenseBundleNormalizer

group = "com.weavechain"
version = "1.0.8"

plugins {
    java
    `maven-publish`
    id("org.jetbrains.dokka") version "1.8.20"
    id("com.github.jk1.dependency-license-report") version "2.4"
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    signing

    id("java-library")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

repositories {
    java

    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
    compileOnly("org.projectlombok:lombok:1.18.28")
    annotationProcessor("org.projectlombok:lombok:1.18.28")

    implementation("org.slf4j:slf4j-api:2.0.0")

    implementation("com.weavechain:curve25519-elisabeth:0.1.5")
    implementation("com.github.aelstad:keccakj:1.1.0")
    implementation("org.bitcoinj:bitcoinj-core:0.17-alpha1")
    implementation("org.msgpack:msgpack-core:0.8.24")
    implementation("io.airlift:aircompressor:0.21")
    implementation("com.github.ben-manes:caffeine:3.1.6") {
        exclude("com.github.ben-manes.caffeine", "simulator")
    }

    implementation("com.google.guava:guava:32.0.0-jre")
    implementation("commons-codec:commons-codec:1.15")
    implementation("com.google.code.gson:gson:2.8.9")

    testCompileOnly("org.projectlombok:lombok:1.18.28")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.28")
    testImplementation("org.testng:testng:7.8.0")
    testImplementation("com.google.truth:truth:1.1.4")
}

tasks.withType<Test>().configureEach {
    useTestNG()
}

val sourcesJar by tasks.registering(Jar::class) {
    classifier = "sources"
    from(sourceSets.main.get().allSource)
}

val dokkaHtml by tasks.getting(org.jetbrains.dokka.gradle.DokkaTask::class)

val javadocJar: TaskProvider<Jar> by tasks.registering(Jar::class) {
    dependsOn(dokkaHtml)
    archiveClassifier.set("javadoc")
    from(dokkaHtml.outputDirectory)
}

publishing {
    repositories {
        maven {
            url = uri("./build/repo")
            name = "Maven"
        }
    }

    publications {
        create<MavenPublication>("Maven") {
            groupId = "com.weavechain"
            artifactId = "bulletproofs"
            version = "1.0.8"
            from(components["java"])
        }
        withType<MavenPublication> {
            artifact(sourcesJar)
            artifact(javadocJar)

            pom {
                name.set(project.name)
                description.set("Bulletproofs Java Implementation")
                url.set("https://github.com/weavechain/bulletproofs")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/mit")
                    }
                }
                issueManagement {
                    system.set("Github")
                    url.set("https://github.com/weavechain/bulletproofs/issues")
                }
                scm {
                    connection.set("scm:git:git://github.com/weavechain/bulletproofs.git")
                    developerConnection.set("scm:git:git@github.com:weavechain/bulletproofs.git")
                    url.set("https://github.com/weavechain/bulletproofs")
                }
                developers {
                    developer {
                        name.set("Ioan Moldovan")
                        email.set("ioan.moldovan@weavechain.com")
                    }
                }
            }
        }
    }
}

signing {
    useGpgCmd()
    sign(configurations.archives.get())
    sign(publishing.publications["Maven"])
}

tasks {
    sourceSets.getByName("test") {
        java.srcDir("src/test/java")
    }

    val releaseJar by creating(Jar::class) {
        archiveClassifier.set("bulletproofs")

        from(sourceSets.main.get().output.classesDirs)
        include("com/weavechain/**")
    }

    artifacts {
        add("archives", releaseJar)
        add("archives", sourcesJar)
    }
}

tasks.withType<PublishToMavenRepository> {
    dependsOn("checkLicense")
}

licenseReport {
    filters = arrayOf<DependencyFilter>(
            LicenseBundleNormalizer(
                    "$rootDir/normalizer-bundle.json",
                    true
            )
    )
    excludeGroups = arrayOf<String>(
    )
    allowedLicensesFile = File("$rootDir/allowed-licenses.json")
}