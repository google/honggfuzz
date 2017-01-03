# !/url/bin/perl -w
# Author: riusksk
# Blog : http://riusksk.me
# Date : 2016-12-16

no  warnings;
use strict;
use LWP::UserAgent;
use Encode;
use URI::Escape;
use Getopt::Long;

my ($keyword, $page, $ext, $help);

GetOptions(
           'g=s' => \$keyword,
           'p=s' => \$page,
           'e=s' => \$ext,
           'h!' => \$help,
           );

if(!defined $ext || defined $help){
    &usage();
}

system("mkdir download_".$ext);

if(defined $keyword) {
    my @fileurls = &google();

    foreach my $fileurl(@fileurls){
        chomp($fileurl);
        if($fileurl){
            print "链接：$fileurl\n";
            download($fileurl);
        }
    }
}


sub usage(){
    print "\n";
    print "[Usage]: perl\t filedownload.pl \n";
    print "\t -g\t Google 搜索语句 \n";
    print "\t -p\t 搜索结果的起始页数\n";
    print "\t -e\t 文件扩展名\n";
    print "\t -h\t 帮助信息\n\n";
    print "[Example]: perl filedownload.pl -g \"inurl:.pdf\" -e \"pdf\" -p 1\n\n";
    exit;
}

sub google{
    my @urls = ();
    my @fileurls = ();
    my $fileurl = "";
    if ($page < 1){
        $page = 1;
    }
    my $start = 100 * ($page-1);
        
    # 通过google搜索文件
    my $ua = new LWP::UserAgent;
    $ua->agent("Mozilla/5.0 (X11; Linux i686; rv:2.0.0) Gecko/20130130");
    $ua->max_redirect( 0 );
    #my $response = $ua->get( "http://www.google.com.au/search?hl=zh-CN&q=".$keyword."+filetype:".$ext."&num=100&start=".$start )
    my $response = $ua->get( "http://www.google.com.hk/search?hl=zh-CN&q=".$keyword."+filetype:".$ext."&num=100&start=".$start )
        or die ("[*] google请求失败，请重试！\n");
    #print $response->content."\n";
    my $content = $response->content;

    if($content=~/did\ not\ match/ig){
        die("[*] 搜索不到相关信息!\n\n");
    }
    
    # 提取搜索结果中的文件链接
    @urls = split(/\/url\?q\=/,$content);
    delete $urls[0];
    foreach $fileurl(@urls){
        my @tmp = split(/\&amp\;/,$fileurl);
        $fileurl = $tmp[0];
        chomp($fileurl);
        $fileurl =~ /(.+?\.$ext)/i;
        $fileurl = $1;
        #print "链接：$fileurl\n";
        push(@fileurls,$fileurl);
    }
    my %seen = ();
    @fileurls = grep(!$seen{$_}++ , @fileurls);  # 删除重复的文件地址
    return @fileurls;
}

sub download(){
    my $url = $_[0];
    print"[*] 下载文件中……\n";
    system("wget --no-check-certificate $url");
    
    
    my @tmp = split(/\//,$url);
    my $filename = pop(@tmp);
    $filename = uri_unescape($filename);

    if(-e $filename){
        system("mv *.".$ext." download_".$ext."/");
        return $filename;
    }
    else{
        print("[*] 无法下载到文件，请重新测试！\n\n");
        return 0;
    }
}
