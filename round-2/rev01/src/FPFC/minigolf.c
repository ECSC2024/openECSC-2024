#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <math.h>

#define DEBUGno

typedef struct _location {
    float x;
    float y;
} location;

typedef struct _wall {
    location start;
    location end;
} wall;


typedef struct _hit {
    float angle;
    float strength;
} hit;

location player = {.x=100.0, .y=90.0};

location hole = {.x=0.0, .y=0.0};

wall walls[] = {{.start={.x=24,.y=32},.end={.x=100,.y=100}},{.start={.x=-32,.y=-67},.end={.x=-100,.y=-53}},{.start={.x=64,.y=-68},.end={.x=14,.y=-17}},{.start={.x=-97,.y=57},.end={.x=-100,.y=74}},{.start={.x=-92,.y=3},.end={.x=-41,.y=20}},{.start={.x=-54,.y=-1},.end={.x=-47,.y=11}},{.start={.x=-4,.y=39},.end={.x=32,.y=-100}},{.start={.x=60,.y=85},.end={.x=-100,.y=100}},{.start={.x=91,.y=-57},.end={.x=66,.y=-66}},{.start={.x=-62,.y=0},.end={.x=8,.y=-67}},{.start={.x=-21,.y=-12},.end={.x=-41,.y=89}},{.start={.x=56,.y=56},.end={.x=56,.y=58}},{.start={.x=-90,.y=-23},.end={.x=-76,.y=-50}},{.start={.x=48,.y=-70},.end={.x=41,.y=-92}},{.start={.x=56,.y=9},.end={.x=100,.y=68}},{.start={.x=36,.y=44},.end={.x=-30,.y=45}},{.start={.x=34,.y=55},.end={.x=25,.y=49}},{.start={.x=8,.y=59},.end={.x=-27,.y=87}},{.start={.x=70,.y=81},.end={.x=68,.y=81}},{.start={.x=4,.y=33},.end={.x=1,.y=43}},{.start={.x=-46,.y=-68},.end={.x=-58,.y=-100}},{.start={.x=77,.y=17},.end={.x=100,.y=-80}},{.start={.x=1,.y=72},.end={.x=-4,.y=72}},{.start={.x=-48,.y=0},.end={.x=-28,.y=11}},{.start={.x=59,.y=-20},.end={.x=35,.y=-38}},{.start={.x=90,.y=-52},.end={.x=100,.y=-100}},{.start={.x=26,.y=100},.end={.x=-30,.y=100}},{.start={.x=-11,.y=18},.end={.x=-9,.y=43}},{.start={.x=-24,.y=-10},.end={.x=-23,.y=-10}},{.start={.x=72,.y=-4},.end={.x=58,.y=10}},{.start={.x=-65,.y=33},.end={.x=-100,.y=45}},{.start={.x=-47,.y=56},.end={.x=-38,.y=7}},{.start={.x=69,.y=-79},.end={.x=93,.y=-84}},{.start={.x=67,.y=95},.end={.x=54,.y=100}},{.start={.x=-76,.y=51},.end={.x=-79,.y=38}},{.start={.x=93,.y=22},.end={.x=91,.y=6}},{.start={.x=-94,.y=-18},.end={.x=-75,.y=-37}},{.start={.x=37,.y=-28},.end={.x=52,.y=22}},{.start={.x=39,.y=45},.end={.x=21,.y=-13}},{.start={.x=-5,.y=53},.end={.x=1,.y=63}},{.start={.x=-11,.y=20},.end={.x=-26,.y=24}},{.start={.x=86,.y=-98},.end={.x=38,.y=-100}},{.start={.x=-24,.y=80},.end={.x=-25,.y=82}},{.start={.x=9,.y=-74},.end={.x=-33,.y=-82}},{.start={.x=37,.y=-89},.end={.x=34,.y=-57}},{.start={.x=57,.y=60},.end={.x=100,.y=100}},{.start={.x=37,.y=-95},.end={.x=34,.y=-100}},{.start={.x=-87,.y=-17},.end={.x=-89,.y=2}},{.start={.x=23,.y=64},.end={.x=26,.y=51}},{.start={.x=-23,.y=98},.end={.x=56,.y=89}},{.start={.x=24,.y=5},.end={.x=20,.y=15}},{.start={.x=-42,.y=57},.end={.x=-37,.y=59}},{.start={.x=79,.y=-47},.end={.x=72,.y=-58}},{.start={.x=4,.y=0},.end={.x=4,.y=0}},{.start={.x=-94,.y=-44},.end={.x=-95,.y=-54}},{.start={.x=76,.y=-11},.end={.x=45,.y=-4}},{.start={.x=-13,.y=-58},.end={.x=-15,.y=-77}},{.start={.x=81,.y=94},.end={.x=80,.y=100}},{.start={.x=-57,.y=-64},.end={.x=-52,.y=-73}},{.start={.x=-43,.y=45},.end={.x=-34,.y=45}},{.start={.x=14,.y=-19},.end={.x=28,.y=-75}},{.start={.x=8,.y=53},.end={.x=6,.y=56}},{.start={.x=55,.y=75},.end={.x=45,.y=77}},{.start={.x=62,.y=-5},.end={.x=46,.y=-2}},{.start={.x=43,.y=34},.end={.x=58,.y=15}},{.start={.x=-15,.y=3},.end={.x=2,.y=10}},{.start={.x=-84,.y=61},.end={.x=-100,.y=100}},{.start={.x=-74,.y=24},.end={.x=-82,.y=31}},{.start={.x=61,.y=7},.end={.x=73,.y=-5}},{.start={.x=7,.y=120},.end={.x=97,.y=172}},{.start={.x=35,.y=54},.end={.x=47,.y=74}},{.start={.x=-79,.y=-4},.end={.x=-88,.y=-5}},{.start={.x=-63,.y=-28},.end={.x=-65,.y=9}},{.start={.x=53,.y=-28},.end={.x=63,.y=-98}},{.start={.x=92,.y=-85},.end={.x=91,.y=-97}},{.start={.x=46,.y=33},.end={.x=38,.y=38}},{.start={.x=100,.y=44},.end={.x=100,.y=57}},{.start={.x=11,.y=49},.end={.x=31,.y=82}},{.start={.x=37,.y=-45},.end={.x=20,.y=-39}},{.start={.x=-22,.y=-43},.end={.x=-42,.y=-58}},{.start={.x=9,.y=-30},.end={.x=12,.y=-28}},{.start={.x=25,.y=83},.end={.x=25,.y=87}},{.start={.x=70,.y=-93},.end={.x=65,.y=-89}},{.start={.x=-18,.y=-84},.end={.x=25,.y=-81}},{.start={.x=4,.y=-73},.end={.x=23,.y=-73}},{.start={.x=-49,.y=87},.end={.x=-91,.y=85}},{.start={.x=66,.y=-76},.end={.x=62,.y=-73}},{.start={.x=41,.y=100},.end={.x=38,.y=107}},{.start={.x=32,.y=-22},.end={.x=35,.y=-18}},{.start={.x=-67,.y=-84},.end={.x=-72,.y=-100}},{.start={.x=96,.y=10},.end={.x=100,.y=-41}},{.start={.x=27,.y=-52},.end={.x=23,.y=-48}},{.start={.x=71,.y=-86},.end={.x=64,.y=-81}},{.start={.x=-60,.y=-26},.end={.x=-46,.y=-18}},{.start={.x=64,.y=0},.end={.x=65,.y=1}},{.start={.x=-100,.y=57},.end={.x=-99,.y=58}},{.start={.x=-88,.y=30},.end={.x=-85,.y=30}},{.start={.x=73,.y=68},.end={.x=100,.y=100}},{.start={.x=67,.y=15},.end={.x=68,.y=18}},{.start={.x=70,.y=91},.end={.x=78,.y=97}},{.start={.x=-80,.y=-9},.end={.x=-81,.y=-6}},{.start={.x=87,.y=57},.end={.x=73,.y=66}},{.start={.x=69,.y=41},.end={.x=76,.y=41}},{.start={.x=-32,.y=12},.end={.x=-31,.y=11}},{.start={.x=44,.y=44},.end={.x=43,.y=51}},{.start={.x=-31,.y=78},.end={.x=-38,.y=75}},{.start={.x=64,.y=-34},.end={.x=87,.y=-33}},{.start={.x=87,.y=-67},.end={.x=80,.y=-80}},{.start={.x=-49,.y=76},.end={.x=-40,.y=78}},{.start={.x=39,.y=-55},.end={.x=38,.y=-60}},{.start={.x=-13,.y=-52},.end={.x=-22,.y=-45}},{.start={.x=-83,.y=84},.end={.x=-85,.y=75}},{.start={.x=-65,.y=-10},.end={.x=-69,.y=9}},{.start={.x=7,.y=44},.end={.x=2,.y=43}},{.start={.x=78,.y=60},.end={.x=76,.y=48}},{.start={.x=66,.y=-45},.end={.x=85,.y=-37}},{.start={.x=-25,.y=-60},.end={.x=-17,.y=-67}},{.start={.x=25,.y=51},.end={.x=20,.y=47}},{.start={.x=-69,.y=32},.end={.x=-82,.y=9}},{.start={.x=-27,.y=-75},.end={.x=-24,.y=-65}},{.start={.x=41,.y=64},.end={.x=52,.y=61}},{.start={.x=-68,.y=-39},.end={.x=-55,.y=-54}},{.start={.x=-15,.y=-59},.end={.x=-30,.y=-54}},{.start={.x=-61,.y=-55},.end={.x=-60,.y=-52}},{.start={.x=25,.y=-88},.end={.x=23,.y=-83}},{.start={.x=65,.y=37},.end={.x=50,.y=26}},{.start={.x=-20,.y=89},.end={.x=-25,.y=86}},{.start={.x=-52,.y=-81},.end={.x=-60,.y=-66}},{.start={.x=67,.y=72},.end={.x=60,.y=81}},{.start={.x=-79,.y=23},.end={.x=-139,.y=-27}},{.start={.x=-86,.y=-2},.end={.x=-87,.y=-1}},{.start={.x=-100,.y=36},.end={.x=-46,.y=30}},{.start={.x=-92,.y=58},.end={.x=-100,.y=93}},{.start={.x=1,.y=-89},.end={.x=0,.y=-84}},{.start={.x=-83,.y=-16},.end={.x=-66,.y=-51}},{.start={.x=-12,.y=52},.end={.x=-9,.y=54}},{.start={.x=42,.y=81},.end={.x=35,.y=66}},{.start={.x=90,.y=83},.end={.x=88,.y=84}},{.start={.x=87,.y=48},.end={.x=98,.y=51}},{.start={.x=-40,.y=-16},.end={.x=-37,.y=4}},{.start={.x=-55,.y=-78},.end={.x=-75,.y=-74}},{.start={.x=65,.y=23},.end={.x=57,.y=30}},{.start={.x=23,.y=17},.end={.x=18,.y=42}},{.start={.x=34,.y=73},.end={.x=28,.y=75}},{.start={.x=14,.y=97},.end={.x=15,.y=98}},{.start={.x=35,.y=-43},.end={.x=37,.y=-44}},{.start={.x=-38,.y=13},.end={.x=-28,.y=13}},{.start={.x=13,.y=58},.end={.x=11,.y=58}},{.start={.x=-52,.y=-28},.end={.x=-38,.y=-54}},{.start={.x=24,.y=-27},.end={.x=-1,.y=38}},{.start={.x=42,.y=63},.end={.x=45,.y=53}},{.start={.x=0,.y=-14},.end={.x=5,.y=-21}},{.start={.x=40,.y=58},.end={.x=41,.y=59}},{.start={.x=5,.y=10},.end={.x=7,.y=11}},{.start={.x=18,.y=50},.end={.x=13,.y=50}},{.start={.x=56,.y=70},.end={.x=58,.y=78}},{.start={.x=-35,.y=-47},.end={.x=-40,.y=-46}},{.start={.x=-97,.y=-75},.end={.x=-70,.y=-88}},{.start={.x=77,.y=45},.end={.x=59,.y=61}},{.start={.x=-6,.y=-74},.end={.x=5,.y=-67}},{.start={.x=-80,.y=-43},.end={.x=-75,.y=-55}},{.start={.x=34,.y=-8},.end={.x=24,.y=-26}},{.start={.x=87,.y=-80},.end={.x=93,.y=-71}},{.start={.x=-68,.y=66},.end={.x=-60,.y=82}},{.start={.x=71,.y=51},.end={.x=61,.y=62}},{.start={.x=46,.y=-33},.end={.x=52,.y=-33}},{.start={.x=32,.y=38},.end={.x=34,.y=40}},{.start={.x=68,.y=-5},.end={.x=79,.y=-10}},{.start={.x=-47,.y=-91},.end={.x=-49,.y=-97}},{.start={.x=-53,.y=9},.end={.x=-41,.y=14}},{.start={.x=93,.y=-75},.end={.x=92,.y=-75}},{.start={.x=-67,.y=-96},.end={.x=-60,.y=-100}},{.start={.x=21,.y=-30},.end={.x=23,.y=-32}},{.start={.x=7,.y=47},.end={.x=11,.y=55}},{.start={.x=-2,.y=90},.end={.x=27,.y=80}},{.start={.x=67,.y=-65},.end={.x=63,.y=-59}},{.start={.x=-36,.y=100},.end={.x=-39,.y=104}},{.start={.x=21,.y=-75},.end={.x=22,.y=-73}},{.start={.x=-69,.y=2},.end={.x=-68,.y=3}},{.start={.x=22,.y=31},.end={.x=24,.y=42}},{.start={.x=-89,.y=66},.end={.x=-93,.y=64}},{.start={.x=90,.y=51},.end={.x=91,.y=51}},{.start={.x=91,.y=-84},.end={.x=79,.y=-90}},{.start={.x=-41,.y=100},.end={.x=-41,.y=95}},{.start={.x=-23,.y=-61},.end={.x=-22,.y=-59}},{.start={.x=38,.y=46},.end={.x=32,.y=52}},{.start={.x=-39,.y=-24},.end={.x=-41,.y=-4}},{.start={.x=-27,.y=-100},.end={.x=-15,.y=-88}},{.start={.x=88,.y=100},.end={.x=77,.y=104}},{.start={.x=58,.y=36},.end={.x=58,.y=33}},{.start={.x=-24,.y=-26},.end={.x=-22,.y=-32}},{.start={.x=-51,.y=32},.end={.x=-99,.y=57}},{.start={.x=-100,.y=23},.end={.x=-89,.y=24}},{.start={.x=50,.y=-13},.end={.x=56,.y=-11}},{.start={.x=-51,.y=-89},.end={.x=-53,.y=-89}}};

hit* hits;

#ifdef DEBUG

void print_hits(size_t hits_length){
    for(int i=0; i<hits_length; i++){
        printf("# Hit %d: angle %f, strength %f\n", i, hits[i].angle, hits[i].strength);
    }
}

void print_player(){
    printf("# Playerx: %f, playery: %f\n", player.x, player.y);
}

void print_hit(location l, float angle, float power){
    printf("# Simulating hit, starting from x: %f, y: %f, angle: %f, power: %f\n", l.x, l.y, angle*360/(2*M_PI), power);
}

#endif


void parse_input_to_hits(char* input, size_t hits_length){
    for(int i=0; i<hits_length; i++){
        int iangle = (input[i*4]-'A')*26+input[i*4+1]-'A';
        int istrength = (input[i*4+2]-'A')*26+input[i*4+3]-'A';
        #ifdef DEBUG
            printf("# parse: %d %d\n", iangle, istrength);
        #endif
        hits[i].angle = ((float)iangle/675.0)*2.0*M_PI;
        hits[i].strength = ((float)istrength/675.0)*25.0;
    }
}

float ccw(location A, location B, location C){ // https://stackoverflow.com/questions/3838329/how-can-i-check-if-two-segments-intersect
    return (C.y-A.y) * (B.x-A.x) > (B.y-A.y) * (C.x-A.x);
}

int do_intersect(location* start, location* end, wall* _wall){
    return ccw(*start,_wall->start,_wall->end) != ccw(*end,_wall->start,_wall->end) && ccw(*start,*end,_wall->start) != ccw(*start,*end,_wall->end);
}

void intersect(location* intersect, location* start, location* end, wall* _wall){
    float s1_x, s1_y, s2_x, s2_y;
    s1_x = end->x - start->x;     s1_y = end->y - start->y;
    s2_x = _wall->end.x - _wall->start.x;     s2_y = _wall->end.y - _wall->start.y;
    float t = ( s2_x * (start->y - _wall->start.y) - s2_y * (start->x - _wall->start.x)) / (-s2_x * s1_y + s1_x * s2_y);
    
    intersect->x = start->x+(t*s1_x);
    intersect->y = start->y+(t*s1_y);
}

void simulate_walls(location* next_location, float* left_power, float* angle){
    size_t number_of_walls=sizeof(walls) / sizeof(walls[0]);
    location ball_end_point={.x=next_location->x, .y=next_location->y}; //
    location newest_intersection={.x=0.0, .y=0.0};
    float ball_consumed_power=*left_power;
    float new_movement_angle=*angle;
    #ifdef DEBUG
            printf("# Number of walls: %ld\n", number_of_walls);
    #endif
    for(size_t i=0; i<number_of_walls; i++){
        wall current_wall=walls[i];
        if(do_intersect(&player, next_location, &current_wall)){ // Check if wall intersects
            
            intersect(&newest_intersection, &player, next_location, &current_wall); // Get intersection point
            float intersection_distance=sqrtf((newest_intersection.x-player.x)*(newest_intersection.x-player.x)+(newest_intersection.y-player.y)*(newest_intersection.y-player.y));
            if(intersection_distance>0.01){
                #ifdef DEBUG
            printf("# Found collision at %f %f distance %f\n", newest_intersection.x, newest_intersection.y, intersection_distance);
            #endif
            if(intersection_distance<ball_consumed_power){ // Calculate intersection distance
                ball_consumed_power=intersection_distance; // Ball consumes less energy
                ball_end_point.x=newest_intersection.x; // And moves less
                ball_end_point.y=newest_intersection.y;
                float wall_angle = atanf((current_wall.end.y-current_wall.start.y)/ (current_wall.end.x - current_wall.start.x));
                if(wall_angle<0){
                    wall_angle+=M_PI;
                }
                float ok_angle=*angle;
                if(ok_angle<0){
                    ok_angle+=M_PI;
                }
                float cross_angle = atan2((tan(ok_angle)-tan(wall_angle)),(1+tan(ok_angle)*tan(wall_angle)));
                #ifdef DEBUG
                printf("# cross_angle %f\n", cross_angle*180/M_PI);
                #endif
                int greater=tanf(wall_angle-ok_angle)>0;
                if(cross_angle<0){
                    cross_angle=-cross_angle;
                }
                if(cross_angle>M_PI/2){
                    cross_angle=M_PI-cross_angle;
                }
                float angle_delta = M_PI-2*cross_angle;

                float new_angle;
                if(greater){
                    new_angle=*angle-M_PI-angle_delta; // A
                }else{
                    new_angle=*angle-M_PI+angle_delta; // B
                }
                #ifdef DEBUG
                printf("# cross_angle %f angle_delta %f new_angle %f\n", cross_angle*180/M_PI, angle_delta*180/M_PI, new_angle*180/M_PI);
                #endif
                if(new_angle>=2*M_PI){
                    new_angle-=2*M_PI;
                }
                if(new_angle<0){
                    new_angle+=2*M_PI;
                }
                new_movement_angle=new_angle;
            }
            }
        }
    }
    next_location->x=ball_end_point.x;
    next_location->y=ball_end_point.y;
    *left_power=*left_power-ball_consumed_power;
    *angle=new_movement_angle;
    return;
}

void get_player_next_location(hit h){
    location tmp_next_location={.x=player.x, .y=player.y};
    float remaining_power=h.strength;
    float movement_angle=h.angle;
    while(remaining_power>0){
        #ifdef DEBUG
        print_hit(tmp_next_location, movement_angle, remaining_power);
        #endif
        float x_movement = remaining_power*cos(movement_angle);
        float y_movement = remaining_power*sin(movement_angle);
        tmp_next_location.x=tmp_next_location.x+x_movement;
        tmp_next_location.y=tmp_next_location.y+y_movement;
        simulate_walls(&tmp_next_location,&remaining_power, &movement_angle); //Finds if there is a collision, in that case stops the ball at the collision point and updates angle and power
        player.x=tmp_next_location.x;
        player.y=tmp_next_location.y;
    }
    #ifdef DEBUG
        print_hit(tmp_next_location, movement_angle, remaining_power);
    #endif
}

void play_game(size_t hits_length){
    for(int i=0; i<hits_length; i++){
        get_player_next_location(hits[i]);
        
        #ifdef DEBUG
        print_player();
        #endif
    }
}

int main(){
    setbuf(stdout, NULL);
    puts("Please input your solution: ");
    char* userinput=NULL;
    size_t userinputlen=0;
    getline(&userinput, &userinputlen, stdin);
    if(strcspn(userinput, "\n")!=strlen(userinput)){
        userinput[strcspn(userinput, "\n")] = 0;
    }
    puts("Checking your input...");
    userinputlen=strlen(userinput);
    if(userinputlen==0 || userinputlen%4!=0){
        puts("Invalid input");
        return -1;
    }
    for(int i=0; i<userinputlen; i++){
        if(userinput[i]<65 || userinput[i]>90){
            puts("Invalid input");
            return -1;
        }
    }
    int hits_length = floor(userinputlen/4);
    hits = (hit*) malloc(sizeof(hit)*hits_length);
    parse_input_to_hits(userinput, hits_length);
    #ifdef DEBUG
    print_hits(hits_length);
    #endif
    play_game(hits_length);


    puts("Check completed! Will you get a flag?");
    if(round(player.x)==round(hole.x) && round(player.y)==round(hole.y)){
        char* flag = getenv("FLAG");
        if(!flag){
            printf("Congratulations! Here is your flag: flag{fakeflag}\n");
        }else{
            printf("Congratulations! Here is your flag: %s\n", flag);
        }
    }
    return 0;
}