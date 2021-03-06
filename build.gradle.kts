plugins {
    id("maven-publish")
    kotlin("multiplatform") version "1.6.21"
    kotlin("plugin.serialization") version "1.6.21"
}

group = "com.sphereon.vdx"
version = "0.2.0-SNAPSHOT"




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
        val dssVersion = "5.10.1"
        val kotlinSerializationVersion = "1.3.2"
        val kotlinDateTimeVersion = "0.3.3"
        val bcVersion = 1.71

        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinSerializationVersion")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:$kotlinDateTimeVersion")
                implementation("io.matthewnelson.kotlin-components:encoding-base64:1.1.1")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinSerializationVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-model:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-document:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-cades:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-pades:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-jades:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-token:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-service:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-signature-rest:$dssVersion")
                implementation("eu.europa.ec.joinup.sd-dss:dss-enumerations:$dssVersion")
                implementation("org.bouncycastle:bcprov-jdk18on:$bcVersion")
                implementation("javax.cache:cache-api:1.1.1")
            }


        }
        val jvmTest by getting {
            dependencies {
                implementation("eu.europa.ec.joinup.sd-dss:dss-test:$dssVersion:tests")
                implementation("eu.europa.ec.joinup.sd-dss:dss-pades-pdfbox:$dssVersion")
                implementation("org.bouncycastle:bcpkix-jdk18on:$bcVersion")
                implementation("org.ehcache:ehcache:3.8.1")
            }
        }
        /* val jsMain by getting
         val jsTest by getting*/
    }
}


repositories {
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
