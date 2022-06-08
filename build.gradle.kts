plugins {
    id("maven-publish")
    kotlin("multiplatform") version "1.6.21"
    kotlin("plugin.serialization") version "1.6.21"
}

group = "com.sphereon.vdx"
version = "0.9.1-SNAPSHOT"


kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "11"
        }
        withJava()
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }



    }
    /* js(BOTH) {
         browser {
             commonWebpackConfig {
                 cssSupport.enabled = true
             }
         }
     }*/
    val hostOs = System.getProperty("os.name")
    val isMingwX64 = hostOs.startsWith("Windows")
    val nativeTarget = when {
        hostOs == "Mac OS X" -> macosX64("native")
        hostOs == "Linux" -> linuxX64("native")
        isMingwX64 -> mingwX64("native")
        else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
    }


    sourceSets {
        all {
            languageSettings.optIn("ExperimentalSerializationApi")
        }

        val dssVersion = "5.10.1"
        val kotlinSerializationVersion = "1.3.2"
        val kotlinDateTimeVersion = "0.3.3"
        val bcVersion = 1.71

        val commonMain by getting {
            dependencies {
                api("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinSerializationVersion")
                api("org.jetbrains.kotlinx:kotlinx-datetime:$kotlinDateTimeVersion")
                api("io.matthewnelson.kotlin-components:encoding-base64:1.1.1")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            dependencies {
                api("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinSerializationVersion")
                api("eu.europa.ec.joinup.sd-dss:dss-model:$dssVersion")
                api("eu.europa.ec.joinup.sd-dss:dss-document:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-cades:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-pades:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-jades:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-token:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-service:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-signature-rest:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-enumerations:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-pades-pdfbox:$dssVersion")
                api("org.bouncycastle:bcprov-debug-jdk18on:$bcVersion")
                api("javax.cache:cache-api:1.1.1")
                api("jakarta.xml.bind:jakarta.xml.bind-api:3.0.1")
                api("org.glassfish.jaxb:jaxb-runtime:2.3.3")

                api("io.github.microutils:kotlin-logging-jvm:2.1.23")

                // todo separate into separate project probably
                api("com.sphereon.vdx:eidas-signature-client-rest-jersey3:1.0.0-SNAPSHOT")

                implementation(project.dependencies.platform("com.azure:azure-sdk-bom:1.2.2"))
                implementation("com.azure:azure-identity")
                implementation("com.azure:azure-security-keyvault-administration")
                implementation("com.azure:azure-security-keyvault-certificates")
                implementation("com.azure:azure-security-keyvault-keys")

            }

        }
        val jvmTest by getting {
            dependencies {
                implementation("eu.europa.ec.joinup.sd-dss:dss-test:$dssVersion:tests")

                implementation("org.bouncycastle:bcpkix-jdk18on:$bcVersion")
                implementation("io.mockk:mockk:1.12.4")

//                implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.2")

                implementation("org.ehcache:ehcache:3.8.1")
                implementation("javax.xml.bind:jaxb-api:2.3.0")

            }
        }

        /*   create("jvmREST") {
               kotlin.srcDir("src/jvmREST/kotlin")
               resources.srcDir("src/jvmREST/resources")
               dependencies  {
   //                implementation(project(":jvmMain"))

               }
           }
           val jvmREST by getting {
               dependencies  {
   //                implementation(project(":jvmMain"))
                   implementation("com.sphereon.vdx:eidas-signature-client-rest-native:0.0.3")
               }
           }*/
        /* val jsMain by getting
         val jsTest by getting*/
    }
}


repositories {
    mavenLocal()
    mavenCentral()
    maven {
        name = "jitpack.io"
        url = uri("https://jitpack.io")
    }
    maven {
        name = "cefdigital"
        url = uri("https://ec.europa.eu/cefdigital/artifact/content/repositories/esignaturedss/")
    }
    maven {
        name = "Sphereon Public"
        url = uri("https://nexus.qa.sphereon.com/repository/sphereon-public/")
    }
}

publishing {
    repositories {
        maven {
            val releasesRepoUrl = uri("https://nexus.qa.sphereon.com/repository/sphereon-opensource-releases/")
            val snapshotsRepoUrl = uri("https://nexus.qa.sphereon.com/repository/sphereon-opensource-snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl


            /**
             * Make sure you have the below properties in the gradle.properties file in your local .gradle folder
             */
            val mavenUser: String? by project
            val mavenPassword: String? by project


            credentials {
                username = mavenUser
                password = mavenPassword
            }
        }
    }
}
